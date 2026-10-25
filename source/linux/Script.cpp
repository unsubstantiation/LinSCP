#include "Script.h"
#include "ProtocolClient.h"
#include "S3Client.h"
#include "S3SigV4.h"
#include "ScpClient.h"
#include "ScriptParams.h"

#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <chrono>
#include <map>
#include <set>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/stat.h>

/* The public half of a key file, which only libssh can
 * read on POSIX. */
#include "SshKeys.h"

#include <unistd.h>

#include "Console.h"
#include "HashUtil.h"
#include "LocalFs.h"
#include "PathUtil.h"
#include "Platform.h"
#include "Texts.h"

namespace linscp {

namespace {

/* Upstream's PartialExt: the staging name a resume-capable transfer
 * writes to until the file is complete. */
const char * const kPartialExt = ".filepart";

/* Upstream's default resume threshold (CopyParam: 100 KB): with
 * 'option resume' at its default 'automatic', a binary file of at least
 * this size is transferred through '.filepart' and can be continued. */
const unsigned long long kDefaultResumeThreshold = 100ull * 1024;

/* A local-directory watcher wakes keepuptodate on file changes; the
 * configured interval remains a full-rescan safety net, and timer polling
 * is what is left when inotify cannot be set up. */
class LocalChangeWatcher
{
public:
    LocalChangeWatcher()
        : mFd(-1), mAvailable(false)
    {}

    ~LocalChangeWatcher()
    {
        if (mFd >= 0)
        {
            close(mFd);
        }
    }

    bool Start(const std::string & root)
    {
        mRoot = root;
        mFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (mFd < 0)
        {
            return false;
        }
        mAvailable = AddDirectoryTree(root, true);
        if (!mAvailable)
        {
            close(mFd);
            mFd = -1;
        }
        return mAvailable;
    }

    bool Available() const { return mAvailable; }

    void WaitForChange(unsigned timeoutMilliseconds)
    {
        if (!mAvailable || mFd < 0)
        {
            return;
        }
        /* The watched root can be removed and recreated while the command is
         * waiting. Re-arm it before the next interval after such a change. */
        if (mWatchedPaths.count(mRoot) == 0)
        {
            AddDirectoryTree(mRoot, true);
        }
        unsigned remaining = timeoutMilliseconds;
        while (remaining > 0 && !Interrupted())
        {
            const unsigned slice = remaining < 250u ? remaining : 250u;
            struct pollfd fd;
            fd.fd = mFd;
            fd.events = POLLIN;
            fd.revents = 0;
            const int ready = poll(&fd, 1, static_cast<int>(slice));
            if (ready == 0)
            {
                remaining -= slice;
                continue;
            }
            if (ready < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                remaining -= slice;
                continue;
            }
            if ((fd.revents & POLLIN) == 0)
            {
                remaining -= slice;
                continue;
            }
            if (DrainEvents())
            {
                return;
            }
            remaining -= slice;
        }
    }

private:
    bool AddDirectoryTree(const std::string & root, bool isRoot = false)
    {
        struct stat rootInfo;
        const int rootStat = isRoot ? stat(root.c_str(), &rootInfo) :
            lstat(root.c_str(), &rootInfo);
        if (rootStat != 0 || !S_ISDIR(rootInfo.st_mode))
        {
            return false;
        }

        std::vector<std::string> pending(1, root);
        bool rootAdded = false;
        for (size_t next = 0; next < pending.size(); next++)
        {
            const std::string directory = pending[next];
            if (mWatchedPaths.count(directory) != 0)
            {
                rootAdded = rootAdded || directory == root;
                continue;
            }
            const int wd = inotify_add_watch(mFd, directory.c_str(),
                IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM |
                IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
            if (wd < 0)
            {
                continue;
            }
            std::map<int, std::string>::iterator watched = mWatches.find(wd);
            if (watched != mWatches.end() && watched->second != directory)
            {
                mWatchedPaths.erase(watched->second);
                watched->second = directory;
            }
            else
            {
                mWatches[wd] = directory;
            }
            mWatchedPaths.insert(directory);
            rootAdded = rootAdded || directory == root;

            DIR * stream = opendir(directory.c_str());
            if (stream == NULL)
            {
                continue;
            }
            struct dirent * item = NULL;
            while ((item = readdir(stream)) != NULL)
            {
                if (strcmp(item->d_name, ".") == 0 ||
                    strcmp(item->d_name, "..") == 0)
                {
                    continue;
                }
                const std::string child = JoinLocalPath(directory, item->d_name);
                struct stat childInfo;
                if (lstat(child.c_str(), &childInfo) == 0 &&
                    S_ISDIR(childInfo.st_mode))
                {
                    pending.push_back(child);
                }
            }
            closedir(stream);
        }
        return rootAdded;
    }

    void ForgetWatch(int wd)
    {
        std::map<int, std::string>::iterator found = mWatches.find(wd);
        if (found != mWatches.end())
        {
            mWatchedPaths.erase(found->second);
            mWatches.erase(found);
        }
    }

    bool DrainEvents()
    {
        bool changed = false;
        alignas(struct inotify_event) char buffer[64 * 1024];
        for (;;)
        {
            const ssize_t length = read(mFd, buffer, sizeof(buffer));
            if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                break;
            }
            if (length <= 0)
            {
                break;
            }
            char * cursor = buffer;
            char * end = buffer + length;
            while (cursor + sizeof(struct inotify_event) <= end)
            {
                const struct inotify_event * event =
                    reinterpret_cast<const struct inotify_event *>(cursor);
                const bool isDirectory = (event->mask & IN_ISDIR) != 0;
                const bool addedDirectory = isDirectory &&
                    (event->mask & (IN_CREATE | IN_MOVED_TO)) != 0;
                if (addedDirectory && event->len != 0)
                {
                    std::map<int, std::string>::const_iterator parent =
                        mWatches.find(event->wd);
                    if (parent != mWatches.end())
                    {
                        AddDirectoryTree(JoinLocalPath(parent->second,
                            event->name));
                    }
                }
                if ((event->mask & (IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_FROM |
                        IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF |
                        IN_Q_OVERFLOW)) != 0 || addedDirectory)
                {
                    changed = true;
                }
                if ((event->mask & (IN_DELETE_SELF | IN_IGNORED)) != 0)
                {
                    ForgetWatch(event->wd);
                }
                else if ((event->mask & IN_MOVE_SELF) != 0)
                {
                    std::map<int, std::string>::const_iterator watched =
                        mWatches.find(event->wd);
                    struct stat info;
                    if (watched == mWatches.end() ||
                        lstat(watched->second.c_str(), &info) != 0 ||
                        !S_ISDIR(info.st_mode))
                    {
                        ForgetWatch(event->wd);
                    }
                }
                cursor += sizeof(struct inotify_event) + event->len;
            }
        }
        return changed;
    }

    int mFd;
    std::string mRoot;
    std::map<int, std::string> mWatches;
    std::set<std::string> mWatchedPaths;
    bool mAvailable;
};

std::string ToLower(const std::string & text)
{
    std::string result = text;
    for (size_t i = 0; i < result.size(); i++)
    {
        if (result[i] >= 'A' && result[i] <= 'Z')
        {
            result[i] = static_cast<char>(result[i] - 'A' + 'a');
        }
    }
    return result;
}

/*
 * The command names the interpreter knows, in the order 'help' lists them.
 * Upstream keeps the same list in its command table and lets an unambiguous
 * prefix stand for a whole name; tools/check_upstream_parity.py fails when
 * the dispatcher grows a command that is not listed here.
 */
const char * const kCommandNames[] = {
    "!", "ascii", "attr", "binary", "bye", "call", "cd", "checksum", "chmod",
    "close", "copyid", "cp", "del", "delsession", "dir", "echo", "edit",
    "end", "etag", "exit", "get", "help", "keepuptodate", "lcd", "lls", "ln",
    "lock", "lpwd", "ls", "man", "md", "mkdir", "mget", "mput", "mv",
    "open", "option", "presets", "property", "pwd", "put", "quit", "recv",
    "rename", "rm", "rmdir", "rmsession", "rmspreset", "send", "session",
    "sessions", "stat", "savepreset", "savesession", "show", "symlink",
    "sync", "synchronize", "terminal", "unlock", "versions", "?"
};

std::vector<std::string> CommandNames()
{
    return std::vector<std::string>(kCommandNames,
        kCommandNames + sizeof(kCommandNames) / sizeof(kCommandNames[0]));
}

/*
 * A command line as it may be written to a log file. A password can reach a
 * log in two ways - inside a site URL and as the value of a '-password='
 * switch - and both are masked here, because an action log is kept, shipped
 * and archived more readily than a terminal. Upstream masks the sensitive
 * parameters of its log the same way.
 */
std::string CensoredForLog(const std::string & line)
{
    std::string result = line;

    /* 'scheme://user:password@host' -> 'scheme://user:***@host' */
    size_t from = 0;
    while (true)
    {
        const size_t scheme = result.find("://", from);
        if (scheme == std::string::npos)
        {
            break;
        }
        const size_t tokenEnd = result.find_first_of(" \t\"'", scheme + 3);
        const size_t at = result.find('@', scheme + 3);
        from = tokenEnd == std::string::npos ? result.size() : tokenEnd;
        if (at == std::string::npos || (tokenEnd != std::string::npos && at > tokenEnd))
        {
            continue;
        }
        const size_t colon = result.find(':', scheme + 3);
        if (colon == std::string::npos || colon > at)
        {
            continue;
        }
        result.replace(colon + 1, at - colon - 1, "***");
        from = colon + 4;
    }

    // Work with complete shell-style tokens: secrets may be quoted after
    // '=' or as a whole "Name=value with spaces" argument. Finding the next
    // literal space/quote leaks the tail of single-quoted and escaped values.
    std::string censored;
    for (size_t at = 0; at < result.size();)
    {
        if (isspace(static_cast<unsigned char>(result[at])))
        {
            censored += result[at++];
            continue;
        }
        const size_t begin = at;
        char quote = 0;
        while (at < result.size())
        {
            const char c = result[at];
            if (c == '\\' && quote != '\'' && at + 1 < result.size())
            {
                at += 2;
                continue;
            }
            if (c == '\'' || c == '"')
            {
                if (quote == c) quote = 0;
                else if (quote == 0) quote = c;
            }
            if (quote == 0 && isspace(static_cast<unsigned char>(c))) break;
            ++at;
        }
        const std::string token = result.substr(begin, at - begin);
        const std::vector<std::string> words = SplitCommandLine(token);
        bool secret = false;
        auto isSecretKey = [](const std::string & name) -> bool {
            return name == "-password" || name == "-passphrase" ||
                name == "proxypassword" || name == "tunnelpassword" ||
                name == "tunnelpassphrase" || name == "tunnelpasswordplain" ||
                name == "tunnelpassphraseplain" || name == "proxypasswordplain";
        };
        if (words.size() == 1)
        {
            const size_t eq = words[0].find('=');
            const std::string name = ToLower(words[0].substr(0, eq));
            secret = eq != std::string::npos && isSecretKey(name);
            if (secret) censored += words[0].substr(0, eq + 1) + "***";
        }
        else
        {
            /* Unclosed quotes make SplitCommandLine return empty; still
             * mask secret switches so broken command lines never leak. */
            std::string stripped = token;
            while (!stripped.empty() && (stripped[0] == '"' || stripped[0] == '\''))
            {
                stripped.erase(0, 1);
            }
            const size_t eq = stripped.find('=');
            if (eq != std::string::npos &&
                isSecretKey(ToLower(stripped.substr(0, eq))))
            {
                secret = true;
                censored += stripped.substr(0, eq + 1) + "***";
            }
        }
        if (!secret) censored += token;
    }
    return censored;
}

bool IsKnownCommand(const std::string & name)
{
    for (size_t i = 0; i < sizeof(kCommandNames) / sizeof(kCommandNames[0]); i++)
    {
        if (name == kCommandNames[i])
        {
            return true;
        }
    }
    return false;
}

/*
 * The '-speed=' limit. It is applied here rather than in a backend: the
 * progress callback runs after every chunk of every transfer, so pausing in
 * it paces the native SFTP engine, the curl path and the ASCII conversion
 * alike, without either of them knowing about bandwidth.
 */
unsigned long long gSpeedLimitBytes = 0;
std::chrono::steady_clock::time_point gSpeedStarted;
unsigned long long gSpeedSeen = 0;

void SetSpeedLimit(unsigned long long bytesPerSecond)
{
    gSpeedLimitBytes = bytesPerSecond;
    gSpeedSeen = 0;
    gSpeedStarted = std::chrono::steady_clock::now();
}

void PaceTransfer(unsigned long long transferred)
{
    if (gSpeedLimitBytes == 0)
    {
        return;
    }
    if (transferred < gSpeedSeen)
    {
        /* A new file started: the schedule restarts with it. */
        gSpeedStarted = std::chrono::steady_clock::now();
    }
    gSpeedSeen = transferred;

    const unsigned long long microseconds =
        transferred * 1000000ULL / gSpeedLimitBytes;
    const std::chrono::steady_clock::time_point due =
        gSpeedStarted + std::chrono::microseconds(microseconds);
    while (due > std::chrono::steady_clock::now())
    {
        /* Short sleeps, so that Ctrl-C still stops a paced transfer. */
        const long long wait = std::chrono::duration_cast<std::chrono::milliseconds>(
            due - std::chrono::steady_clock::now()).count();
        SleepMilliseconds(wait > 100 ? 100u : static_cast<unsigned>(wait > 0 ? wait : 1));
        if (Interrupted())
        {
            return;
        }
    }
}

/*
 * Keeps the limit of one command in force while its files transfer and clears
 * it afterwards, on every return path. 'member' mirrors the value for the
 * curl backends, which ask curl itself to pace the connection.
 */
class SpeedLimitForThisCommand
{
public:
    SpeedLimitForThisCommand(unsigned kBytesPerSecond, unsigned * member) :
        mMember(member)
    {
        SetSpeedLimit(kBytesPerSecond * 1024ULL);
        if (mMember != NULL)
        {
            *mMember = kBytesPerSecond;
        }
    }
    ~SpeedLimitForThisCommand()
    {
        SetSpeedLimit(0);
        if (mMember != NULL)
        {
            *mMember = 0;
        }
    }

private:
    SpeedLimitForThisCommand(const SpeedLimitForThisCommand &);
    SpeedLimitForThisCommand & operator=(const SpeedLimitForThisCommand &);

    unsigned * mMember;
};

void ProgressCallback(unsigned long long transferred, unsigned long long total, void * ctx)
{
    (void)total;
    (void)ctx;
    PaceTransfer(transferred);
    Console::Instance().TransferProgress(transferred);
}

/*
 * Whether 'text' begins with 'prefix' and carries a value after it.
 *
 * The character more than the prefix is deliberate: a switch given with
 * nothing behind its '=' is refused as unknown rather than read as an
 * empty value, because an empty '-filemask=' or '-transfer=' would
 * otherwise silently change what a transfer does. A switch whose value may
 * legitimately be empty says so at its own place in the argument loop, the
 * way '-rawsettings' and '-preset=' do.
 */
bool StartsWith(const std::string & text, const char * prefix)
{
    size_t len = strlen(prefix);
    return text.size() > len && text.compare(0, len, prefix) == 0;
}

enum class ConfirmationResult
{
    Accepted,
    Declined,
    Unavailable
};

ConfirmationResult ConfirmDestructiveAction(const std::string & question)
{
    Console & console = Console::Instance();
    if (!console.IsInteractive())
    {
        console.Error(Texts::Translate("Cannot confirm this action without a terminal; run "
            "interactively or use 'option confirm off' in a trusted script."));
        return ConfirmationResult::Unavailable;
    }
    if (console.Confirm(question, false))
    {
        return ConfirmationResult::Accepted;
    }
    console.Status(Texts::Translate("Cancelled."));
    return ConfirmationResult::Declined;
}

bool StringListContains(const std::vector<std::string> & list,
    const std::string & value)
{
    for (size_t i = 0; i < list.size(); i++)
    {
        if (list[i] == value)
        {
            return true;
        }
    }
    return false;
}

bool NameListContains(const LscpNames * names, const std::string & value)
{
    if (names == NULL)
    {
        return false;
    }
    for (int i = 0; i < names->count; i++)
    {
        if (names->names[i].filename != NULL && value == names->names[i].filename)
        {
            return true;
        }
    }
    return false;
}

bool ParseOctalPermissions(const std::string & text, unsigned long & permissions)
{
    if (text.empty())
    {
        return false;
    }
    unsigned long value = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] < '0' || text[i] > '7')
        {
            return false;
        }
        value = value * 8 + static_cast<unsigned long>(text[i] - '0');
        if (value > 07777)
        {
            return false;
        }
    }
    permissions = value;
    return true;
}

/*
 * Reads the parameters of a '-rawsettings[=N]' switch: the 'name=value'
 * parameters that follow it, at most N of them when the switch carries a
 * number, which is upstream's idiom for a switch that takes a list. 'index'
 * is the position of the switch and is advanced past the parameters it took.
 */
bool CollectRawSettings(const std::vector<std::string> & args, size_t & index,
    std::vector<RawSetting> & settings, std::string & error)
{
    const std::string & arg = args[index];
    int cap = -1;
    const size_t equals = arg.find('=');
    if (equals != std::string::npos)
    {
        const std::string count = arg.substr(equals + 1);
        char * end = NULL;
        const long parsed = count.empty() ? -1 :
            strtol(count.c_str(), &end, 10);
        if (end == NULL || *end != '\0' || parsed < 0 ||
            static_cast<long>(static_cast<int>(parsed)) != parsed)
        {
            error = Texts::Translate(
                "The value of '-rawsettings' is the number of settings that "
                "follow it, as in '-rawsettings=2'.");
            return false;
        }
        cap = static_cast<int>(parsed);
    }
    int taken = 0;
    while (index + 1 < args.size() && (cap < 0 || taken < cap))
    {
        const std::string & next = args[index + 1];
        if (next.empty() || next[0] == '-' ||
            next.find('=') == std::string::npos)
        {
            if (cap < 0)
            {
                break;
            }
            error = Texts::Translate(
                "'{name}' is not a 'name=value' session setting.",
                {{"name", next}});
            return false;
        }
        const size_t eq = next.find('=');
        settings.push_back(RawSetting(next.substr(0, eq), next.substr(eq + 1)));
        index++;
        taken++;
    }
    if (cap >= 0 && taken < cap)
    {
        error = Texts::Translate(
            "'-rawsettings={count}' was given, but only {taken} setting "
            "parameter(s) follow.",
            {{"count", std::to_string(cap)}, {"taken", std::to_string(taken)}});
        return false;
    }
    return true;
}

/*
 * Applies collected settings to a session: the proxy names it has always
 * taken, plus the FTP and TLS policy of this build (FtpPasvMode,
 * FtpUseMlsd, Ftps, MinTlsVersion, TlsCertificateFile, ...). The first
 * setting this build does not apply stops it and is named, because a
 * session that silently ignores a setting connects somewhere else than
 * the user asked for.
 */
bool ApplyRawSettings(const std::vector<RawSetting> & settings,
    SessionOptions & options, std::string & error)
{
    for (size_t i = 0; i < settings.size(); i++)
    {
        if (!ApplySessionRawSetting(settings[i].first, settings[i].second,
                options, error))
        {
            return false;
        }
    }
    return true;
}

/*
 * A switch that carries on/off: upstream's TOptions::SwitchValue. No value
 * means on, "on" and "off" are accepted in any case, and so is a whole
 * number whose zero means off. Anything else is refused rather than read
 * as one of the two by accident.
 */
bool ParseSwitchBool(const std::string & text, bool & value)
{
    if (text.empty() || ToLower(text) == "on")
    {
        value = true;
        return true;
    }
    if (ToLower(text) == "off")
    {
        value = false;
        return true;
    }
    char * end = NULL;
    const long number = strtol(text.c_str(), &end, 10);
    if (end != NULL && *end == '\0')
    {
        value = number != 0;
        return true;
    }
    return false;
}

/*
 * The switches of 'open' onto the options of the site they open, whether
 * that site came from a URL or from the store. Only a switch that was given
 * changes anything, so the defaults of the command line and the settings a
 * stored site was saved with survive.
 */
bool ApplyOpenSwitches(const OpenSwitches & switches, SessionOptions & options,
    std::string & error)
{
    if (switches.hostKeyGiven)
    {
        options.hostKey = switches.hostKey;
    }
    if (switches.passwordGiven)
    {
        options.password = switches.password;
    }
    if (switches.userNameGiven)
    {
        options.userName = switches.userName;
    }
    if (switches.privateKeyGiven)
    {
        options.privateKeyFile = switches.privateKeyFile;
    }
    if (switches.passphraseGiven)
    {
        options.keyPassphrase = switches.passphrase;
    }
    /* The connection's own timeout, TLS mode, FTP data policy and TLS
     * client certificate. Upstream reads the same four switches from the
     * 'open' command line and applies them to a stored site as well. */
    if (switches.timeoutGiven)
    {
        options.timeoutSecs = switches.timeoutSecs;
    }
    if (switches.implicitGiven)
    {
        options.tls.ftpsMode = switches.implicitValue ? 1 : 0;
    }
    if (switches.explicitGiven)
    {
        /* TFtps 2 is explicit SSL, 3 explicit TLS; upstream keeps the
         * deprecated '-explicitssl' spelling on 2 and maps '-explicit' to
         * explicit TLS. */
        options.tls.ftpsMode = switches.explicitValue ?
            (switches.explicitSsl ? 2 : 3) : 0;
    }
    if (switches.passiveGiven)
    {
        options.ftp.passiveMode = switches.passiveValue;
    }
    if (switches.clientCertGiven)
    {
        options.tls.clientCertificate = ExpandTilde(switches.clientCertificate);
    }
    return ApplyRawSettings(switches.rawSettings, options, error);
}

} // namespace

Script::Script() :
    mBatchMode(Console::Instance().IsBatchMode() ? BatchMode::Abort : BatchMode::Off),
    mBatchConfigured(false),
    mConfirm(true),
    mResumeMode(ResumeMode::Automatic),
    mExit(false),
    mErrors(0),
    mLastCommandFailed(false),
    mEditMaxSize(EditOptions::kDefaultMaxSize),
    mTransferMode(TransferMode::Binary),
    mOptionMaskUsed(false),
    mFailOnNoMatch(false),
    mEchoCommands(false),
    mReconnectSeconds(0),
    mSyncDeleteDefault(false),
    mSpeedLimit(0),
    mServerLoop(false)
{
}

bool Script::AbortAfterFileError() const
{
    /* 'batch on'/'batch abort' stop everything, including the remaining
     * files of a multi-file command; 'continue'/'off' go on. */
    return mBatchMode == BatchMode::Abort || mBatchMode == BatchMode::On;
}

bool Script::RequireConnection()
{
    if (mSession.IsOpen() && mSession.IsAlive())
    {
        return true;
    }
    /* The session died in the middle of the script. With
     * 'option reconnecttime' the client reopens it once (within the
     * configured number of seconds) and restores the directory. */
    if (mSession.IsOpen() && mReconnectSeconds > 0)
    {
        const SessionOptions options = mSession.Options();
        const std::string lastDirectory = mRemoteDirectory;
        Console::Instance().Status(Texts::Translate(
            "The connection was lost; reconnecting to {host}...",
            {{"host", mSession.HostDescription()}}));
        mSession.Close();
        std::string error;
        if (!mSession.Open(options, error))
        {
            Console::Instance().Error(Texts::CannotOpenSession(
                options.hostName, error));
            mErrors++;
            return false;
        }
        mRemoteDirectory = options.initialDirectory.empty() ?
            "/" : options.initialDirectory;
        if (!lastDirectory.empty() && lastDirectory != "/")
        {
            LscpAttrs attrs = {};
            if (RemoteStat(lastDirectory, &attrs, error) ==
                LSCP_SFTP_STAT_EXISTS)
            {
                mRemoteDirectory = lastDirectory;
            }
        }
        return true;
    }
    if (mSession.IsOpen())
    {
        mSession.Close();
        mRemoteDirectory.clear();
    }
    Console::Instance().Error(Texts::NotConnected());
    mErrors++;
    return false;
}

bool Script::RemoteListDir(const std::string & path, LscpNames *& names, std::string & error)
{
    error.clear();
    names = NULL;
    if (UseNativeSftp(mSession.Options().protocol))
    {
        names = lscp_sftp_list_dir(path.c_str());
        if (names == NULL)
        {
            error = lscp_sftp_error();
            return false;
        }
        return true;
    }
    names = new LscpNames();
    bool ok = ProtocolClient::List(mSession.Options(), path, names, error);
    if (!ok)
    {
        delete names;
        names = NULL;
        return false;
    }
    return true;
}

void Script::RemoteFreeNames(LscpNames * names)
{
    if (names == NULL)
    {
        return;
    }
    if (UseNativeSftp(mSession.Options().protocol))
    {
        lscp_sftp_free_names(names);
    }
    else
    {
        ProtocolClient::FreeNames(names);
        delete names;
    }
}

/*
 * The XML action log's spelling of what the listings already know: the
 * nine permission letters without the type character (upstream's
 * Rights.Text), and the '<file>' of an 'ls'/'stat' element from one set of
 * attributes. A member the backend did not report stays absent, as in
 * upstream's RecordFile.
 */
static std::string XmlPermissionsText(unsigned long permissions)
{
    const std::string text = FormatPermissions(permissions);
    return text.size() > 1 ? text.substr(1) : text;
}

static XmlFileInfo XmlFileInfoFromAttrs(const std::string & name,
    const LscpAttrs & attrs)
{
    XmlFileInfo file;
    file.name = name;
    if ((attrs.flags & LSCP_ATTR_PERMISSIONS) != 0)
    {
        const std::string text = FormatPermissions(attrs.permissions);
        if (!text.empty())
        {
            file.type = static_cast<char>(toupper(
                static_cast<unsigned char>(text[0])));
        }
        file.permissions = XmlPermissionsText(attrs.permissions);
        if (file.type != 'D' && (attrs.flags & LSCP_ATTR_SIZE) != 0)
        {
            file.hasSize = true;
            file.size = attrs.size;
        }
    }
    else if ((attrs.flags & LSCP_ATTR_SIZE) != 0)
    {
        file.hasSize = true;
        file.size = attrs.size;
    }
    if ((attrs.flags & LSCP_ATTR_ACMODTIME) != 0 && attrs.mtime != 0)
    {
        file.hasModification = true;
        file.modification = attrs.mtime;
    }
    if ((attrs.flags & LSCP_ATTR_UIDGID) != 0)
    {
        file.owner = std::to_string(attrs.uid);
        file.group = std::to_string(attrs.gid);
    }
    return file;
}

/* One server-side copy in the XML log, from whichever of its exits
 * CopyRemoteOneFile takes. */
static void XmlLogCopy(const std::string & from, const std::string & to,
    bool success, const std::string & error)
{
    XmlParams params;
    params.push_back(std::make_pair("filename", from));
    params.push_back(std::make_pair("destination", to));
    Console::Instance().XmlAction("cp", params, success,
        success ? std::string() : error);
}

int Script::RemoteStat(const std::string & path, LscpAttrs * attrs, std::string & error)
{
    error.clear();
    if (UseNativeSftp(mSession.Options().protocol))
    {
        int st = lscp_sftp_stat(path.c_str(), attrs);
        if (st != LSCP_SFTP_STAT_EXISTS)
        {
            error = lscp_sftp_error();
        }
        return st;
    }
    return ProtocolClient::Stat(mSession.Options(), path, attrs, error);
}

int Script::RemoteGet(const std::string & remote, const std::string & local,
    unsigned long long resumeOffset, bool preserveTime,
    unsigned long long * size, LscpProgressFn progress, void * ctx,
    std::string & error, bool append, const std::string & versionId)
{
    error.clear();
    int res = 0;
    if (!versionId.empty() &&
        ToLower(mSession.Options().protocol) != "s3")
    {
        error = Texts::Translate(
            "Version-specific downloads are available only for S3.");
        res = -1;
    }
    else if (UseNativeSftp(mSession.Options().protocol))
    {
        res = append ?
            lscp_sftp_get_append(remote.c_str(), local.c_str(), size, progress, ctx) :
            lscp_sftp_get_resume(remote.c_str(), local.c_str(), resumeOffset, size,
                progress, ctx);
        if (res != 0)
        {
            error = lscp_sftp_error();
        }
        else if (preserveTime)
        {
            LscpAttrs attrs = {};
            if (lscp_sftp_stat(remote.c_str(), &attrs) == LSCP_SFTP_STAT_EXISTS &&
                (attrs.flags & LSCP_ATTR_ACMODTIME) != 0 && attrs.mtime != 0)
            {
                /* Some servers report an atime of zero; keep the
                 * modification time in that case. Setting a local time
                 * after a download is not a remote operation, so the XML
                 * log has no '<touch>' for it, as upstream has none. */
                SetFileTimes(local,
                    attrs.atime != 0 ? attrs.atime : attrs.mtime,
                    attrs.mtime);
            }
        }
    }
    else if (!versionId.empty())
    {
        res = S3Client::Get(mSession.Options(), remote, local, resumeOffset,
            preserveTime, size, progress, ctx, error, mSpeedLimit, versionId);
    }
    else
    {
        res = ProtocolClient::Get(mSession.Options(), remote, local, resumeOffset,
            preserveTime, size, progress, ctx, error, mSpeedLimit);
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("filename", remote));
        params.push_back(std::make_pair("destination", local));
        if (res == 0)
        {
            const LocalFileInfo downloaded = StatLocal(local);
            if (downloaded.exists)
            {
                params.push_back(std::make_pair("size",
                    std::to_string(downloaded.size)));
            }
        }
        Console::Instance().XmlAction("download", params, res == 0,
            res == 0 ? std::string() : error);
    }
    return res;
}

int Script::RemotePut(const std::string & local, const std::string & remote,
    int permissions, unsigned long long resumeOffset, bool preserveTime,
    unsigned long long * size, LscpProgressFn progress, void * ctx,
    std::string & error, bool append)
{
    error.clear();
    int res = 0;
    if (UseNativeSftp(mSession.Options().protocol))
    {
        res = append ?
            lscp_sftp_put_append(local.c_str(), remote.c_str(), permissions, size,
                progress, ctx) :
            lscp_sftp_put_resume(local.c_str(), remote.c_str(), permissions,
                resumeOffset, size, progress, ctx);
        if (res != 0)
        {
            error = lscp_sftp_error();
        }
        else if (preserveTime)
        {
            /* The SFTP protocol has no way to carry the timestamps in the
             * transfer itself, so set them once the file is complete. */
            const LocalFileInfo info = StatLocal(local);
            if (info.exists && info.mtime != 0)
            {
                const int touchRes = lscp_sftp_set_times(remote.c_str(),
                    info.atime != 0 ? info.atime : info.mtime, info.mtime);
                {
                    XmlParams touchParams;
                    touchParams.push_back(std::make_pair("filename", remote));
                    touchParams.push_back(std::make_pair("modification",
                        Console::XmlTimestamp(info.mtime)));
                    Console::Instance().XmlAction("touch", touchParams,
                        touchRes == 0,
                        touchRes == 0 ? std::string() :
                            std::string(lscp_sftp_error()));
                }
                if (touchRes != 0)
                {
                    Console::Instance().Status(Texts::Translate(
                        "Could not set the timestamps of '{path}': {reason}",
                        {{"path", remote}, {"reason", lscp_sftp_error()}}));
                }
            }
        }
    }
    else
    {
        res = ProtocolClient::Put(mSession.Options(), local, remote, permissions,
            resumeOffset, preserveTime, size, progress, ctx, error, mSpeedLimit);
        if (res == 0 && ProtocolClient::IsDavProtocol(mSession.Options().protocol))
        {
            // A successful write changes the resource's ETag on the server,
            // so the precondition recorded for the previous version is now
            // stale. Clear it so the next write is unconditional unless the
            // user explicitly records the new tag with 'etag -get' and
            // 'etag -match=' again; leaving a stale tag would make the
            // next upload fail with 412 even though the user did not ask
            // to guard it.
            if (mSession.Options().davEtags.find(remote) !=
                mSession.Options().davEtags.end())
            {
                mSession.ClearDavEtag(remote);
            }
        }
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("filename", local));
        params.push_back(std::make_pair("destination", remote));
        if (res == 0)
        {
            const LocalFileInfo uploaded = StatLocal(local);
            if (uploaded.exists)
            {
                params.push_back(std::make_pair("size",
                    std::to_string(uploaded.size)));
            }
        }
        Console::Instance().XmlAction("upload", params, res == 0,
            res == 0 ? std::string() : error);
    }
    return res;
}

/* The timestamps of a local file onto a remote path, used when a transfer
 * preserves the time of a directory as well as of its files. */
int Script::RemoteSetTimes(const std::string & path, unsigned long atime,
    unsigned long mtime, std::string & error)
{
    error.clear();
    XmlParams params;
    params.push_back(std::make_pair("filename", path));
    params.push_back(std::make_pair("modification",
        Console::XmlTimestamp(mtime)));
    if (UseNativeScp(mSession.Options().protocol))
    {
        /* 'touch' sets both times to the one value, which is all a shell
         * offers; the modification time is the one a comparison reads. */
        if (!ScpClient::SetTimes(mSession.Options(), path, atime, mtime, error))
        {
            Console::Instance().XmlAction("touch", params, false, error);
            return -1;
        }
        Console::Instance().XmlAction("touch", params, true);
        return 0;
    }
    if (!UseNativeSftp(mSession.Options().protocol))
    {
        error = Texts::Translate(
            "Setting the timestamps of a directory needs the native SFTP "
            "transport or an SCP session.");
        Console::Instance().XmlAction("touch", params, false, error);
        return -1;
    }
    const int res = lscp_sftp_set_times(path.c_str(), atime, mtime);
    if (res != 0)
    {
        error = lscp_sftp_error();
    }
    Console::Instance().XmlAction("touch", params, res == 0,
        res == 0 ? std::string() : error);
    return res;
}

/* Download/Upload with the plan's transfer mode: 'ascii'/'automatic'
 * convert the line endings around the binary transfer, exactly like
 * get/put do. The transfer stages through '.filepart' when the mode does
 * not convert and the persistent 'option resume' setting allows it -
 * 'on' always, 'automatic' from upstream's default 100 KB threshold. */
int Script::RemoteGetMode(const std::string & remote, const std::string & local,
    TransferMode mode, unsigned long long sourceSize,
    unsigned long long * size, std::string & error)
{
    const bool converts = WantsAsciiConversion(mode, RemoteFileName(remote));
    const bool eligible = !converts &&
        (mResumeMode == ResumeMode::On ||
         (mResumeMode == ResumeMode::Automatic &&
          sourceSize >= kDefaultResumeThreshold));
    TransferStage stage;
    if (!ResolveStage(eligible, false, local, sourceSize, stage, error) ||
        !PrepareStage(stage, error))
    {
        return -1;
    }
    int result = 0;
    if (stage.complete)
    {
        if (size != NULL)
        {
            *size = sourceSize;
        }
    }
    else
    {
        result = RemoteGet(remote, stage.partPath, stage.resumeOffset, true, size,
            ProgressCallback, NULL, error);
    }
    if (result != 0)
    {
        return result;
    }
    if (converts)
    {
        unsigned long long converted = 0;
        if (!ConvertToUnixLineEndings(local, converted, error))
        {
            return -1;
        }
        if (size != NULL)
        {
            *size = converted;
        }
    }
    if (!FinishStage(stage, error))
    {
        return -1;
    }
    return 0;
}

int Script::RemotePutMode(const std::string & local, const std::string & remote,
    TransferMode mode, unsigned long long sourceSize,
    unsigned long long * size, std::string & error)
{
    if (!WantsAsciiConversion(mode, LocalFileName(local)))
    {
        const bool eligible = mResumeMode == ResumeMode::On ||
            (mResumeMode == ResumeMode::Automatic &&
             sourceSize >= kDefaultResumeThreshold);
        TransferStage stage;
        if (!ResolveStage(eligible, true, remote, sourceSize, stage, error) ||
            !PrepareStage(stage, error))
        {
            return -1;
        }
        int result = 0;
        if (stage.complete)
        {
            if (size != NULL)
            {
                *size = sourceSize;
            }
        }
        else
        {
            result = RemotePut(local, stage.partPath, -1, stage.resumeOffset, true,
                size, ProgressCallback, NULL, error);
        }
        if (result != 0)
        {
            return result;
        }
        if (!FinishStage(stage, error))
        {
            return -1;
        }
        return 0;
    }
    std::string tempPath;
    if (!MakeCRLFUploadCopy(local, tempPath, error))
    {
        return -1;
    }
    const int result = RemotePut(tempPath, remote, -1, 0, true, size,
        ProgressCallback, NULL, error);
    remove(tempPath.c_str());
    return result;
}

int Script::RemoteRemove(const std::string & path, std::string & error)
{
    error.clear();
    int res = 0;
    if (UseNativeSftp(mSession.Options().protocol))
    {
        res = lscp_sftp_remove(path.c_str());
        if (res != 0)
        {
            error = lscp_sftp_error();
        }
    }
    else
    {
        res = ProtocolClient::Remove(mSession.Options(), path, error);
    }
    if (res == 0 && ProtocolClient::IsDavProtocol(mSession.Options().protocol))
    {
        if (mSession.Options().davEtags.find(path) !=
            mSession.Options().davEtags.end())
        {
            mSession.ClearDavEtag(path);
        }
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("filename", path));
        Console::Instance().XmlAction("rm", params, res == 0,
            res == 0 ? std::string() : error);
    }
    return res;
}

int Script::RemoteRemoveDir(const std::string & path, std::string & error)
{
    error.clear();
    int res = 0;
    if (UseNativeSftp(mSession.Options().protocol))
    {
        res = lscp_sftp_rmdir(path.c_str());
        if (res != 0)
        {
            error = lscp_sftp_error();
        }
    }
    else
    {
        res = ProtocolClient::RemoveDir(mSession.Options(), path, error);
    }
    if (res == 0 && ProtocolClient::IsDavProtocol(mSession.Options().protocol))
    {
        if (mSession.Options().davEtags.find(path) !=
            mSession.Options().davEtags.end())
        {
            mSession.ClearDavEtag(path);
        }
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("filename", path));
        Console::Instance().XmlAction("rm", params, res == 0,
            res == 0 ? std::string() : error);
    }
    return res;
}

int Script::RemoteMakeDir(const std::string & path, int permissions, std::string & error)
{
    error.clear();
    int res = 0;
    if (UseNativeSftp(mSession.Options().protocol))
    {
        res = lscp_sftp_mkdir(path.c_str(), permissions);
        if (res != 0)
        {
            error = lscp_sftp_error();
        }
    }
    else
    {
        res = ProtocolClient::MakeDir(mSession.Options(), path, error);
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("filename", path));
        Console::Instance().XmlAction("mkdir", params, res == 0,
            res == 0 ? std::string() : error);
    }
    return res;
}

int Script::RemoteRename(const std::string & from, const std::string & to, std::string & error)
{
    error.clear();
    int res = 0;
    if (UseNativeSftp(mSession.Options().protocol))
    {
        res = lscp_sftp_rename(from.c_str(), to.c_str());
        if (res != 0)
        {
            error = lscp_sftp_error();
        }
    }
    else
    {
        res = ProtocolClient::Move(mSession.Options(), from, to, error);
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("filename", from));
        params.push_back(std::make_pair("destination", to));
        Console::Instance().XmlAction("mv", params, res == 0,
            res == 0 ? std::string() : error);
    }
    return res;
}

/* The three remote operations the editor needs. They are thin wrappers
 * so that Editor.cpp never has to know about the session. */
int Script::StatForEdit(const std::string & path, LscpAttrs & attrs, std::string & error)
{
    return RemoteStat(path, &attrs, error);
}

int Script::DownloadForEdit(const std::string & remote, const std::string & local,
    bool preserveTime, std::string & error)
{
    return RemoteGet(remote, local, 0, preserveTime, NULL, ProgressCallback, NULL, error);
}

int Script::UploadForEdit(const std::string & local, const std::string & remote,
    bool preserveTime, std::string & error)
{
    return RemotePut(local, remote, -1, 0, preserveTime, NULL, ProgressCallback,
        NULL, error);
}

int Script::RemoteSetPermissions(const std::string & path, int permissions,
    std::string & error)
{
    error.clear();
    int res = 0;
    if (UseNativeSftp(mSession.Options().protocol))
    {
        res = lscp_sftp_set_permissions(path.c_str(), permissions);
        if (res != 0)
        {
            error = lscp_sftp_error();
        }
    }
    else
    {
        res = ProtocolClient::SetPermissions(mSession.Options(), path,
            permissions, error);
    }
    {
        /* Upstream writes the letters ('rwxr-xr-x'), not the octal the
         * user typed: the log is for a reader that compares them with
         * the permissions of an 'ls' element. */
        XmlParams params;
        params.push_back(std::make_pair("filename", path));
        params.push_back(std::make_pair("permissions",
            XmlPermissionsText(static_cast<unsigned long>(permissions))));
        Console::Instance().XmlAction("chmod", params, res == 0,
            res == 0 ? std::string() : error);
    }
    return res;
}

bool Script::OpenSite(const std::vector<std::string> & args)
{
    /* Command-line options are defaults for every opened site. Explicit
     * values in the URL or on this command override them; do not reset the
     * port or credentials here (doing so made -port/-username/-password
     * silently ineffective). */
    SessionOptions options = mDefaults;
    options.hostName.clear();
    options.initialDirectory.clear();

    std::string url;
    /*
     * The switches are collected before the target of 'open' is known,
     * because they apply to a stored site exactly as they apply to a URL:
     * a URL brings no session settings of its own, a stored site brings the
     * ones it was saved with, and the command's switches change either.
     */
    OpenSwitches switches;
    for (size_t i = 0; i < args.size(); i++)
    {
        /* Upstream reads a switch name without regard to case, so
         * '-HOSTKEY=' is the same switch as '-hostkey='. */
        const std::string lower = ToLower(args[i]);
        if (StartsWith(lower, "-hostkey="))
        {
            switches.hostKey = args[i].substr(strlen("-hostkey="));
            switches.hostKeyGiven = true;
        }
        else if (StartsWith(lower, "-password="))
        {
            switches.password = args[i].substr(strlen("-password="));
            switches.passwordGiven = true;
        }
        else if (StartsWith(lower, "-username="))
        {
            switches.userName = args[i].substr(strlen("-username="));
            switches.userNameGiven = true;
        }
        else if (StartsWith(lower, "-privatekey="))
        {
            switches.privateKeyFile = args[i].substr(strlen("-privatekey="));
            switches.privateKeyGiven = true;
        }
        else if (StartsWith(lower, "-passphrase="))
        {
            switches.passphrase = args[i].substr(strlen("-passphrase="));
            switches.passphraseGiven = true;
        }
        else if (StartsWith(lower, "-timeout="))
        {
            /* The server response timeout of this connection, in
             * seconds, like upstream's '-timeout='. */
            const std::string value = args[i].substr(strlen("-timeout="));
            char * end = NULL;
            const long seconds = value.empty() ? 0 : strtol(value.c_str(), &end, 10);
            if (value.empty() || end == NULL || *end != '\0' || seconds <= 0 ||
                seconds > INT_MAX)
            {
                Console::Instance().Error(Texts::WrongArguments("open",
                    Texts::Translate(
                        "The value of '-timeout' is the server response timeout in "
                        "seconds, a positive whole number.")));
                mErrors++;
                return false;
            }
            switches.timeoutSecs = static_cast<int>(seconds);
            switches.timeoutGiven = true;
        }
        else if (lower == "-implicit" || StartsWith(lower, "-implicit="))
        {
            bool enabled = true;
            if (!ParseSwitchBool(args[i].substr(strlen("-implicit") +
                    (lower.size() > strlen("-implicit") ? 1 : 0)), enabled))
            {
                Console::Instance().Error(Texts::WrongArguments("open",
                    Texts::Translate(
                        "The value of '-implicit' must be on or off (a number "
                        "other than zero means on).")));
                mErrors++;
                return false;
            }
            switches.implicitGiven = true;
            switches.implicitValue = enabled;
            switches.explicitGiven = false;
        }
        else if (lower == "-explicit" || StartsWith(lower, "-explicit=") ||
            lower == "-explicittls" || StartsWith(lower, "-explicittls=") ||
            lower == "-explicitssl" || StartsWith(lower, "-explicitssl="))
        {
            const bool ssl = StartsWith(lower, "-explicitssl");
            const std::string name = ssl ? "-explicitssl" :
                StartsWith(lower, "-explicittls") ? "-explicittls" : "-explicit";
            bool enabled = true;
            if (lower.size() > name.size() &&
                !ParseSwitchBool(args[i].substr(name.size() + 1), enabled))
            {
                Console::Instance().Error(Texts::WrongArguments("open",
                    Texts::Translate(
                        "The value of '{switch}' must be on or off (a number "
                        "other than zero means on).", {{"switch", name}})));
                mErrors++;
                return false;
            }
            switches.explicitGiven = true;
            switches.explicitValue = enabled;
            switches.explicitSsl = ssl;
            switches.implicitGiven = false;
        }
        else if (lower == "-passive" || StartsWith(lower, "-passive="))
        {
            bool enabled = true;
            if (!ParseSwitchBool(args[i].substr(strlen("-passive") +
                    (lower.size() > strlen("-passive") ? 1 : 0)), enabled))
            {
                Console::Instance().Error(Texts::WrongArguments("open",
                    Texts::Translate(
                        "The value of '-passive' must be on or off (a number "
                        "other than zero means on).")));
                mErrors++;
                return false;
            }
            switches.passiveGiven = true;
            switches.passiveValue = enabled;
        }
        else if (StartsWith(lower, "-clientcert="))
        {
            switches.clientCertificate = args[i].substr(strlen("-clientcert="));
            switches.clientCertGiven = true;
        }
        else if (StartsWith(lower, "-sessionname="))
        {
            switches.sessionName = args[i].substr(strlen("-sessionname="));
            switches.sessionNameGiven = true;
        }
        else if (lower == "-rawsettings" ||
            StartsWith(lower, "-rawsettings="))
        {
            std::string rawError;
            if (!CollectRawSettings(args, i, switches.rawSettings, rawError))
            {
                Console::Instance().Error(Texts::WrongArguments("open",
                    rawError));
                mErrors++;
                return false;
            }
        }
        else if (StartsWith(args[i], "-"))
        {
            Console::Instance().Error(Texts::WrongArguments("open",
                Texts::Translate("Unknown switch '{switch}'.", {{"switch", args[i]}})));
            mErrors++;
            return false;
        }
        else if (url.empty())
        {
            url = args[i];
        }
        else
        {
            Console::Instance().Error(Texts::WrongArguments("open",
                Texts::Translate("Unexpected argument '{argument}'.",
                    {{"argument", args[i]}})));
            mErrors++;
            return false;
        }
    }

    if (url.empty())
    {
        Console::Instance().Error(Texts::WrongArguments("open",
            Texts::Translate("Syntax: open sftp://[user[:password]@]host[:port]/[path]")));
        mErrors++;
        return false;
    }

    /* A stored session name is not a URL: 'open web1' connects to the
     * session that was saved under that name. */
    if (url.find("://") == std::string::npos && mSessions.Find(url) != NULL)
    {
        return OpenStoredSite(mSessions.Find(url)->name, switches);
    }

    std::string error;
    if (!ParseSiteUrl(url, options, error))
    {
        Console::Instance().Error(error);
        mErrors++;
        return false;
    }
    if (!ApplyOpenSwitches(switches, options, error))
    {
        Console::Instance().Error(Texts::WrongArguments("open", error));
        mErrors++;
        return false;
    }
    if (options.userName.empty())
    {
        options.userName = CurrentUserName();
    }

    if (mSession.IsOpen())
    {
        CloseSite(std::vector<std::string>());
    }
    mHomeDirectory.clear();
    mStoredSessionName.clear();

    Console::Instance().Status(Texts::Translate("Connecting to {host}...", {{"host", options.hostName}}));
    if (!mSession.Open(options, error))
    {
        Console::Instance().Error(Texts::CannotOpenSession(options.hostName, error));
        mErrors++;
        return false;
    }

    if (UseNativeSftp(mSession.Options().protocol))
    {
        if (lscp_sftp_init() != 0)
        {
            Console::Instance().Error(lscp_sftp_error());
            mSession.Close();
            mErrors++;
            return false;
        }

        /* The directory the server starts us in is the home directory,
         * whatever 'cd' target the site configuration asked for. */
        char * home = lscp_sftp_realpath(".");
        if (home != NULL)
        {
            mHomeDirectory = home;
            free(home);
        }
        std::string initial = options.initialDirectory.empty() ?
            std::string(".") : options.initialDirectory;
        char * canonical = lscp_sftp_realpath(initial.c_str());
        if (canonical == NULL)
        {
            Console::Instance().Error(lscp_sftp_error());
            mSession.Close();
            mErrors++;
            return false;
        }
        mRemoteDirectory = canonical;
        free(canonical);
    }
    else if (UseNativeScp(mSession.Options().protocol))
    {
        /*
         * An SCP session runs its commands in the server's shell, and a
         * shell starts in a directory: that is the home directory 'cd'
         * with no argument goes to, and the site's initial path is
         * resolved against it. Both answers come from one command, so a
         * symlink or a relative path becomes the absolute one every later
         * command sends, and a directory the server will not change into
         * fails the open here - where the reason can still be reported -
         * instead of turning into a listing error two commands later.
         */
        std::string home;
        std::string resolved;
        if (!ScpClient::ResolveHomeAndInitial(mSession.Options(),
                options.initialDirectory, home, resolved, error))
        {
            Console::Instance().Error(Texts::CannotOpenSession(options.hostName,
                error));
            mSession.Close();
            mErrors++;
            return false;
        }
        mHomeDirectory = home;
        mRemoteDirectory = resolved;
    }
    else
    {
        mRemoteDirectory = options.initialDirectory.empty() ?
            std::string("/") : options.initialDirectory;
        mHomeDirectory = mRemoteDirectory;
    }

    /* The XML log's '<session>' root is named after the connection, the
     * way upstream names it: 'user@host' for an ad-hoc URL, or the name
     * '-sessionname=' gave it. It records where the session went, never
     * how it was authenticated: no password is part of the format. */
    mSessionDisplayName = switches.sessionNameGiven ? switches.sessionName :
        (options.hostName.empty() ? std::string("session") : options.hostName);
    Console::Instance().XmlSessionName(switches.sessionNameGiven ?
        switches.sessionName :
        (options.userName.empty() ? options.hostName :
            options.userName + "@" + options.hostName));

    Console::Instance().Status(Texts::Translate("Connected, the remote directory is {path}", {{"path", mRemoteDirectory}}));
    return true;
}

void Script::CloseSite(const std::vector<std::string> & args)
{
    /* Upstream checks the session first, then accepts an optional
     * 1-based index of the session to close. Only one connection exists
     * here, so index 1 is the only one that resolves. */
    if (!mSession.IsOpen())
    {
        Console::Instance().Error(Texts::NotConnected());
        mErrors++;
        return;
    }
    if (args.size() > 1)
    {
        Console::Instance().Error(Texts::WrongArguments("close",
            Texts::Translate("Syntax: close [<index>].")));
        mErrors++;
        return;
    }
    if (!args.empty() && args[0] != "1")
    {
        Console::Instance().Error(Texts::Translate(
            "Invalid session index '{index}'.", {{"index", args[0]}}));
        mErrors++;
        return;
    }
    const std::string name = mSessionDisplayName.empty() ?
        (mSession.Options().hostName.empty() ? std::string("session") :
            mSession.Options().hostName) : mSessionDisplayName;
    mSession.Close();
    mRemoteDirectory.clear();
    mHomeDirectory.clear();
    mSessionDisplayName.clear();
    mStoredSessionName.clear();
    /* The XML log has no element for closing: the '<group>' of this
     * command closing is the record, as it is upstream. */
    Console::Instance().WriteLine(Texts::SessionClosed(name));
}

bool Script::ChangeRemoteDirectory(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() > 1)
    {
        Console::Instance().Error(Texts::WrongArguments("cd",
            Texts::Translate("Syntax: cd [<directory>]")));
        mErrors++;
        return false;
    }
    /* Without an argument, go to the home directory, like upstream. */
    std::string path = args.empty() ? mHomeDirectory :
        ResolveRemotePath(mRemoteDirectory, args[0]);
    if (path.empty())
    {
        path = "/";
    }
    if (UseNativeSftp(mSession.Options().protocol))
    {
        char * canonical = lscp_sftp_realpath(path.c_str());
        if (canonical == NULL)
        {
            Console::Instance().Error(Texts::RemoteError("change directory to", path,
                lscp_sftp_error()));
            mErrors++;
            XmlParams params;
            params.push_back(std::make_pair("cwd", path));
            Console::Instance().XmlAction("cwd", params, false,
                lscp_sftp_error());
            return false;
        }
        mRemoteDirectory = canonical;
        free(canonical);
    }
    else if (UseNativeScp(mSession.Options().protocol))
    {
        /* 'cd <path> && pwd' is the server's own answer, so a directory
         * that is not there is refused instead of becoming the working
         * directory of every command that follows. */
        std::string resolved;
        std::string error;
        if (!ScpClient::ResolvePath(mSession.Options(), path, resolved, error))
        {
            Console::Instance().Error(Texts::RemoteError("change directory to",
                path, error));
            mErrors++;
            XmlParams params;
            params.push_back(std::make_pair("cwd", path));
            Console::Instance().XmlAction("cwd", params, false, error);
            return false;
        }
        mRemoteDirectory = resolved;
    }
    else
    {
        mRemoteDirectory = path;
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("cwd", mRemoteDirectory));
        Console::Instance().XmlAction("cwd", params, true);
    }
    Console::Instance().WriteLine(mRemoteDirectory);
    return true;
}

void Script::PrintRemoteDirectory()
{
    if (!RequireConnection())
    {
        return;
    }
    Console::Instance().WriteLine(mRemoteDirectory);
}

void Script::PrintRemoteEntry(const std::string & name, const LscpName & entry,
    bool longFormat)
{
    if (!longFormat)
    {
        Console::Instance().WriteLine(name);
        return;
    }
    if (entry.longname != NULL && entry.longname[0] != '\0')
    {
        Console::Instance().WriteLine(entry.longname);
        return;
    }
    std::string line = FormatPermissions(entry.attrs.permissions);
    line += "  1";
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "  %-8lu %-8lu %12llu",
        entry.attrs.uid, entry.attrs.gid, entry.attrs.size);
    line += buffer;
    line += " " + FormatFileTime(entry.attrs.mtime) + " " + name;
    Console::Instance().WriteLine(line);
}

/*
 * Upstream prints "No files found matching '<mask>'." when a mask matched
 * nothing and only turns it into a script error when the option
 * failonnomatch is on; the reason from the operating system follows the
 * sentence when there is one.
 */
void Script::NoMatch(const std::string & mask, const std::string & error)
{
    std::string message = "No files found matching '" + mask + "'.";
    if (!error.empty())
    {
        message += " " + error;
    }
    if (mFailOnNoMatch)
    {
        Console::Instance().Error(message);
        mErrors++;
    }
    else
    {
        Console::Instance().WriteLine(message);
    }
}

bool Script::ListRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    bool longFormat = true;
    std::string target;
    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string & arg = args[i];
        if (arg.size() > 1 && arg[0] == '-')
        {
            for (size_t j = 1; j < arg.size(); j++)
            {
                switch (arg[j])
                {
                case 'a': /* entries starting with a dot are always listed */
                    break;
                case 'l':
                    longFormat = true;
                    break;
                case '1':
                    longFormat = false;
                    break;
                default:
                    Console::Instance().Error(Texts::WrongArguments("ls",
                        Texts::Translate("Syntax: ls [-al1] [<directory>[/<mask>]]")));
                    mErrors++;
                    return false;
                }
            }
        }
        else if (target.empty())
        {
            target = arg;
        }
        else
        {
            Console::Instance().Error(Texts::WrongArguments("ls",
                Texts::Translate("Syntax: ls [-al1] [<directory>[/<mask>]]")));
            mErrors++;
            return false;
        }
    }
    /* A trailing component with wildcards is a mask: list the parent
     * directory and show only the matching entries. */
    std::string mask;
    if (!target.empty())
    {
        const std::string leaf = RemoteFileName(target);
        if (HasWildcard(leaf))
        {
            mask = leaf;
            target = RemoteDirName(target);
        }
    }
    std::string path = target.empty() ? mRemoteDirectory :
        ResolveRemotePath(mRemoteDirectory, target);
    Console::Instance().Status(Texts::ReadingDirectory(path));
    LscpNames * names = NULL;
    std::string readError;
    if (!RemoteListDir(path, names, readError))
    {
        Console::Instance().Error(Texts::CannotReadDirectory(path, readError));
        mErrors++;
        XmlParams params;
        params.push_back(std::make_pair("destination", path));
        Console::Instance().XmlActionFiles("ls", params,
            std::vector<XmlFileInfo>(), false, readError);
        return false;
    }
    int count = 0;
    std::vector<XmlFileInfo> listed;
    for (int i = 0; i < names->count; i++)
    {
        std::string name = names->names[i].filename != NULL ?
            names->names[i].filename : "";
        if (name == "." || name == "..")
        {
            continue;
        }
        if (!mask.empty() && !MatchesMask(mask, name))
        {
            continue;
        }
        PrintRemoteEntry(name, names->names[i], longFormat);
        listed.push_back(XmlFileInfoFromAttrs(name, names->names[i].attrs));
        count++;
    }
    RemoteFreeNames(names);
    {
        /* Only an explicit 'ls' reaches the XML log, as upstream: the
         * listings a transfer makes for itself are not operations the
         * script asked to see. The entries are the ones printed, with
         * the mask applied and the dot entries left out. */
        XmlParams params;
        params.push_back(std::make_pair("destination", path));
        Console::Instance().XmlActionFiles("ls", params, listed, true);
    }
    if (!mask.empty() && count == 0)
    {
        NoMatch(mask, std::string());
    }
    Console::Instance().Status(Texts::DirectoryRead(count));
    return true;
}

bool Script::ListS3Versions(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() > 1 || (!args.empty() && !args[0].empty() &&
        args[0][0] == '-'))
    {
        Console::Instance().Error(Texts::WrongArguments("versions",
            Texts::Translate("Syntax: versions [<object-or-prefix>]")));
        mErrors++;
        return false;
    }
    if (ToLower(mSession.Options().protocol) != "s3")
    {
        Console::Instance().Error(Texts::WrongArguments("versions",
            Texts::Translate(
                "The 'versions' command is available only for S3 sessions.")));
        mErrors++;
        return false;
    }

    const std::string path = args.empty() ? mRemoteDirectory :
        ResolveRemotePath(mRemoteDirectory, args[0]);
    std::vector<S3ObjectVersion> versions;
    std::string error;
    if (!S3Client::ListVersions(mSession.Options(), path, versions, error))
    {
        Console::Instance().Error(Texts::Translate(
            "Could not list S3 object versions for '{path}': {reason}",
            {{"path", path}, {"reason", error}}));
        mErrors++;
        return false;
    }
    if (versions.empty())
    {
        Console::Instance().WriteLine(Texts::Translate(
            "No S3 object versions found for '{path}'.", {{"path", path}}));
        return true;
    }

    Console::Instance().WriteLine(Texts::Translate(
        "Object versions for '{path}':", {{"path", path}}));
    const size_t bucketEnd = path.find('/', 1);
    const std::string bucketRoot = bucketEnd == std::string::npos ? path :
        path.substr(0, bucketEnd);
    for (size_t i = 0; i < versions.size(); i++)
    {
        const S3ObjectVersion & item = versions[i];
        const std::string state = item.isDeleteMarker ?
            Texts::Translate("delete marker") : item.isLatest ?
            Texts::Translate("latest") : Texts::Translate("version");
        const std::string size = item.isDeleteMarker ? "-" :
            std::to_string(item.size);
        const std::string modified = item.mtime == 0 ? "?" :
            FormatFileTime(item.mtime);
        Console::Instance().WriteLine(state + "  " + bucketRoot + "/" +
            item.key + "  " + item.versionId + "  " + size + "  " + modified);
    }
    return true;
}

bool Script::ChangeLocalDirectory(const std::vector<std::string> & args)
{
    std::string error;
    if (args.size() != 1)
    {
        Console::Instance().Error(Texts::WrongArguments("lcd", Texts::Translate("Syntax: lcd <directory>")));
        mErrors++;
        return false;
    }
    std::string current = GetLocalDirectory(error);
    if (current.empty())
    {
        Console::Instance().Error(error);
        mErrors++;
        return false;
    }
    std::string path = ResolveLocalPath(current, args[0]);
    if (!SetLocalDirectory(path, error))
    {
        Console::Instance().Error(Texts::LocalError("change the directory",
            path, error));
        mErrors++;
        return false;
    }
    /* Upstream prints the directory after changing into it, like 'cd'. */
    std::string after = GetLocalDirectory(error);
    if (after.empty())
    {
        after = path;
    }
    Console::Instance().WriteLine(after);
    return true;
}

void Script::PrintLocalDirectory()
{
    std::string error;
    std::string current = GetLocalDirectory(error);
    if (current.empty())
    {
        Console::Instance().Error(error);
        mErrors++;
        return;
    }
    Console::Instance().WriteLine(current);
}

bool Script::ExpandRemote(const std::string & pattern, std::vector<std::string> & paths,
    std::string & error)
{
    paths.clear();
    if (!HasWildcard(pattern))
    {
        paths.push_back(ResolveRemotePath(mRemoteDirectory, pattern));
        return true;
    }
    std::string absolute = ResolveRemotePath(mRemoteDirectory, pattern);
    std::string dir = RemoteDirName(absolute);
    std::string mask = RemoteFileName(absolute);
    if (dir.empty())
    {
        dir = "/";
    }
    LscpNames * names = NULL;
    if (!RemoteListDir(dir, names, error))
    {
        return false;
    }
    for (int i = 0; i < names->count; i++)
    {
        std::string name = names->names[i].filename != NULL ? names->names[i].filename : "";
        if (!MatchesMask(mask, name))
        {
            continue;
        }
        if (name == "." || name == "..")
        {
            continue;
        }
        paths.push_back(JoinRemotePath(dir, name));
    }
    RemoteFreeNames(names);
    return true;
}

bool Script::CreateRemoteDirectoryRecursive(const std::string & path, std::string & error)
{
    error.clear();
    if (path.empty() || path == "/")
    {
        return true;
    }
    LscpAttrs attrs = {};
    int st = RemoteStat(path, &attrs, error);
    if (st == LSCP_SFTP_STAT_EXISTS)
    {
        if ((attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 && (attrs.permissions & 0040000) != 0)
        {
            return true;
        }
        error = Texts::Translate("Path '{path}' exists and is not a directory.",
            {{"path", path}});
        return false;
    }
    std::string parent = RemoteDirName(path);
    if (!parent.empty() && parent != path && parent != "/")
    {
        if (!CreateRemoteDirectoryRecursive(parent, error))
        {
            return false;
        }
    }
    if (RemoteMakeDir(path, -1, error) != 0)
    {
        return false;
    }
    return true;
}

bool Script::ConfirmObsolete(const std::string & side, const std::string & path,
    bool isDirectory)
{
    if (!mConfirm)
    {
        return true;
    }
    const ConfirmationResult confirmation = ConfirmDestructiveAction(
        Texts::Translate("Delete obsolete {side} {kind} '{path}'?", {{"side", Texts::Translate(side.c_str())},
            {"kind", Texts::Translate(isDirectory ? "directory" : "file")}, {"path", path}}));
    if (confirmation == ConfirmationResult::Accepted)
    {
        return true;
    }
    if (confirmation == ConfirmationResult::Unavailable)
    {
        mErrors++;
    }
    return false;
}

bool Script::RemoveLocalItemRecursive(const std::string & path)
{
    const LocalFileInfo info = StatLocal(path);
    std::string error;
    if (info.isDir)
    {
        std::vector<std::string> entries;
        if (!ListLocalDirectory(path, entries, error))
        {
            Console::Instance().Error(Texts::LocalError("read directory", path, error));
            mErrors++;
            return false;
        }
        bool success = true;
        for (size_t i = 0; i < entries.size(); i++)
        {
            if (!RemoveLocalItemRecursive(JoinLocalPath(path, entries[i])))
            {
                success = false;
            }
        }
        if (!RemoveLocalDirectory(path, error))
        {
            Console::Instance().Error(Texts::LocalError("remove directory", path, error));
            mErrors++;
            return false;
        }
        Console::Instance().Status(Texts::Translate(
            "Removed local directory '{path}'.", {{"path", path}}));
        return success;
    }
    if (!RemoveLocalFile(path, error))
    {
        Console::Instance().Error(Texts::LocalError("remove file", path, error));
        mErrors++;
        return false;
    }
    Console::Instance().Status(Texts::Translate(
        "Removed local file '{path}'.", {{"path", path}}));
    return true;
}

bool Script::RemoveRemoteItemRecursive(const std::string & path)
{
    LscpAttrs attrs = {};
    std::string error;
    const int st = RemoteStat(path, &attrs, error);
    const bool isDir = st == LSCP_SFTP_STAT_EXISTS &&
        (attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
        (attrs.permissions & 0040000) != 0;
    if (isDir)
    {
        LscpNames * names = NULL;
        std::string listError;
        if (!RemoteListDir(path, names, listError))
        {
            Console::Instance().Error(Texts::RemoteError("read directory", path,
                listError));
            mErrors++;
            return false;
        }
        bool success = true;
        for (int i = 0; i < names->count; i++)
        {
            const char * rawName = names->names[i].filename;
            if (rawName == NULL)
            {
                continue;
            }
            const std::string name(rawName);
            if (name == "." || name == "..")
            {
                continue;
            }
            if (!RemoveRemoteItemRecursive(JoinRemotePath(path, name)))
            {
                success = false;
            }
        }
        RemoteFreeNames(names);
        if (RemoteRemoveDir(path, error) != 0)
        {
            Console::Instance().Error(Texts::RemoteError("remove directory", path,
                error));
            mErrors++;
            return false;
        }
        Console::Instance().Status(Texts::Translate(
            "Removed remote directory '{path}'.", {{"path", path}}));
        return success;
    }
    if (RemoteRemove(path, error) != 0)
    {
        Console::Instance().Error(Texts::RemoteError("remove file", path, error));
        mErrors++;
        return false;
    }
    Console::Instance().Status(Texts::Translate(
        "Removed remote file '{path}'.", {{"path", path}}));
    return true;
}

bool Script::DownloadDirectoryRecursive(const std::string & remoteDir,
    const std::string & localDir, const TransferFlags & flags,
    unsigned long long & bytesTransferred, const std::string & relPrefix)
{
    std::string error;
    if (!CreateLocalDirectoryRecursive(localDir, error))
    {
        Console::Instance().Error(Texts::LocalError("create directory", localDir, error));
        mErrors++;
        return false;
    }

    LscpNames * names = NULL;
    std::string dirErr;
    if (!RemoteListDir(remoteDir, names, dirErr))
    {
        Console::Instance().Error(Texts::RemoteError("read directory", remoteDir, dirErr));
        mErrors++;
        return false;
    }

    bool success = true;
    for (int i = 0; i < names->count; i++)
    {
        const char * rawName = names->names[i].filename;
        if (rawName == NULL)
        {
            continue;
        }
        std::string name(rawName);
        if (name == "." || name == "..")
        {
            continue;
        }

        std::string childRemote = JoinRemotePath(remoteDir, name);
        std::string childLocal = JoinLocalPath(localDir, name);

        bool childIsDir = (names->names[i].attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
            (names->names[i].attrs.permissions & 0040000) != 0;

        if (!childIsDir && (names->names[i].attrs.flags & LSCP_ATTR_PERMISSIONS) == 0)
        {
            LscpAttrs a = {};
            if (RemoteStat(childRemote, &a, dirErr) == LSCP_SFTP_STAT_EXISTS)
            {
                childIsDir = (a.flags & LSCP_ATTR_PERMISSIONS) != 0 && (a.permissions & 0040000) != 0;
            }
        }

        const std::string childRel = relPrefix.empty() ? name :
            relPrefix + "/" + name;
        const unsigned long long childSize =
            (names->names[i].attrs.flags & LSCP_ATTR_SIZE) != 0 ?
            names->names[i].attrs.size : 0;
        const unsigned long childTime =
            (names->names[i].attrs.flags & LSCP_ATTR_ACMODTIME) != 0 ?
            names->names[i].attrs.mtime : 0;

        if (childIsDir)
        {
            /* A directory is pruned only by an exclusion. */
            if (!flags.mask.empty() &&
                !flags.mask.Accepts(name, true, 0, 0, childRel))
            {
                continue;
            }
            if (!DownloadDirectoryRecursive(childRemote, childLocal, flags,
                bytesTransferred, childRel))
            {
                success = false;
                if (AbortAfterFileError())
                {
                    RemoteFreeNames(names);
                    return false;
                }
            }
            if (flags.deleteSource)
            {
                RemoteRemoveDir(childRemote, dirErr);
            }
        }
        else
        {
            if (!flags.mask.empty() &&
                !flags.mask.Accepts(name, false, childSize, childTime, childRel))
            {
                continue;
            }
            LocalFileInfo localInfo = StatLocal(childLocal);
            if (flags.newerOnly && localInfo.exists &&
                (names->names[i].attrs.flags & LSCP_ATTR_ACMODTIME) != 0 &&
                localInfo.mtime >= names->names[i].attrs.mtime)
            {
                continue;
            }
            unsigned long long size = 0;
            unsigned long long totalSize = (names->names[i].attrs.flags & LSCP_ATTR_SIZE) != 0 ?
                names->names[i].attrs.size : 0;
            const bool convertsAscii = WantsAsciiConversion(flags.transferMode, name);
            TransferStage stage;
            if (!ResolveStage(!convertsAscii && !flags.append && Resumes(flags, totalSize), false,
                    childLocal, totalSize, stage, dirErr))
            {
                Console::Instance().Error(Texts::LocalError(
                    "inspect the destination", childLocal, dirErr));
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    RemoteFreeNames(names);
                    return false;
                }
                continue;
            }
            if (mConfirm && localInfo.exists && !stage.continuing && !flags.append)
            {
                ConfirmationResult confirmation = ConfirmDestructiveAction(
                    Texts::Translate("Overwrite local file '{path}'?", {{"path", childLocal}}));
                if (confirmation != ConfirmationResult::Accepted)
                {
                    if (confirmation == ConfirmationResult::Unavailable)
                    {
                        mErrors++;
                    }
                    continue;
                }
            }
            if (!PrepareStage(stage, dirErr))
            {
                Console::Instance().Error(Texts::LocalError(
                    "prepare the destination", childLocal, dirErr));
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    RemoteFreeNames(names);
                    return false;
                }
                continue;
            }

            Console::Instance().TransferStart(name, totalSize);
            int result = 0;
            if (stage.complete)
            {
                size = totalSize;
            }
            else
            {
                result = RemoteGet(childRemote, stage.partPath, stage.resumeOffset,
                    flags.preserveTime, &size, ProgressCallback, NULL, dirErr,
                    flags.append);
            }
            Console::Instance().TransferEnd(result == 0);
            if (result != 0)
            {
                Console::Instance().Error(Texts::TransferFailed(childRemote, dirErr));
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    RemoteFreeNames(names);
                    return false;
                }
                continue;
            }
            if (WantsAsciiConversion(flags.transferMode, name))
            {
                unsigned long long converted = 0;
                if (!ConvertToUnixLineEndings(stage.partPath, converted, dirErr))
                {
                    Console::Instance().Error(Texts::LocalError(
                    "convert the line endings", childLocal, dirErr));
                    mErrors++;
                    success = false;
                    if (AbortAfterFileError())
                    {
                        RemoteFreeNames(names);
                        return false;
                    }
                    continue;
                }
                size = converted;
            }
            if (flags.preserveTime && (names->names[i].attrs.flags & LSCP_ATTR_ACMODTIME) != 0)
            {
                SetFileTimes(stage.partPath, names->names[i].attrs.atime,
                    names->names[i].attrs.mtime);
            }
            if (!FinishStage(stage, dirErr))
            {
                Console::Instance().Error(dirErr);
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    RemoteFreeNames(names);
                    return false;
                }
                continue;
            }
            bytesTransferred += size;
            Console::Instance().Status(Texts::FileTransferred(childLocal, size));
            if (flags.deleteSource)
            {
                RemoteRemove(childRemote, dirErr);
            }
        }
    }

    /*
     * 'synchronize -delete': everything in the local target directory
     * that the remote source does not have is obsolete. The source is
     * never touched.
     */
    if (flags.deleteObsolete)
    {
        std::vector<std::string> localEntries;
        std::string listError;
        if (!ListLocalDirectory(localDir, localEntries, listError))
        {
            Console::Instance().Error(Texts::LocalError("read directory", localDir,
                listError));
            mErrors++;
            success = false;
        }
        for (size_t i = 0; i < localEntries.size(); i++)
        {
            if (NameListContains(names, localEntries[i]))
            {
                continue;
            }
            const std::string obsolete = JoinLocalPath(localDir, localEntries[i]);
            const LocalFileInfo obsoleteInfo = StatLocal(obsolete);
            const bool obsoleteIsDir = obsoleteInfo.isDir;
            const std::string obsoleteRel = relPrefix.empty() ?
                localEntries[i] : relPrefix + "/" + localEntries[i];
            if (!flags.mask.empty() &&
                !flags.mask.Accepts(localEntries[i], obsoleteIsDir,
                    obsoleteInfo.size, obsoleteInfo.mtime, obsoleteRel))
            {
                continue;
            }
            if (!ConfirmObsolete("local", obsolete, obsoleteIsDir))
            {
                success = false;
                continue;
            }
            if (!RemoveLocalItemRecursive(obsolete))
            {
                success = false;
            }
        }
    }

    /*
     * '-preservetime=all': the directory itself gets the time of its remote
     * source once, after everything inside it was written (writing a file
     * updates the parent directory again, which is why this happens here and
     * not while the entries are copied).
     */
    if (success && flags.preserveTimeDirs && flags.preserveTime)
    {
        LscpAttrs attrs = {};
        std::string timeError;
        if (RemoteStat(remoteDir, &attrs, timeError) == LSCP_SFTP_STAT_EXISTS &&
            (attrs.flags & LSCP_ATTR_ACMODTIME) != 0 && attrs.mtime != 0)
        {
            SetFileTimes(localDir, attrs.atime != 0 ? attrs.atime : attrs.mtime,
                attrs.mtime);
        }
    }

    RemoteFreeNames(names);
    return success;
}

bool Script::UploadDirectoryRecursive(const std::string & localDir,
    const std::string & remoteDir, const TransferFlags & flags,
    unsigned long long & bytesTransferred, const std::string & relPrefix)
{
    std::string error;
    if (!CreateRemoteDirectoryRecursive(remoteDir, error))
    {
        Console::Instance().Error(Texts::RemoteError("create directory", remoteDir, error));
        mErrors++;
        return false;
    }

    std::vector<std::string> entries;
    if (!ListLocalDirectory(localDir, entries, error))
    {
        Console::Instance().Error(Texts::LocalError("read directory", localDir, error));
        mErrors++;
        return false;
    }

    bool success = true;
    for (size_t i = 0; i < entries.size(); i++)
    {
        const std::string & name = entries[i];
        std::string childLocal = JoinLocalPath(localDir, name);
        std::string childRemote = JoinRemotePath(remoteDir, name);

        const std::string childRel = relPrefix.empty() ? name :
            relPrefix + "/" + name;

        LocalFileInfo info = StatLocal(childLocal);
        if (info.isDir)
        {
            /* A directory is pruned only by an exclusion. */
            if (!flags.mask.empty() &&
                !flags.mask.Accepts(name, true, 0, 0, childRel))
            {
                continue;
            }
            if (!UploadDirectoryRecursive(childLocal, childRemote, flags,
                bytesTransferred, childRel))
            {
                success = false;
                if (AbortAfterFileError())
                {
                    return false;
                }
            }
            if (flags.deleteSource)
            {
                std::string removeError;
                RemoveLocalDirectory(childLocal, removeError);
            }
        }
        else if (info.isRegular)
        {
            if (!flags.mask.empty() &&
                !flags.mask.Accepts(name, false, info.size, info.mtime, childRel))
            {
                continue;
            }
            LscpAttrs remoteInfo = {};
            const int remoteStat = RemoteStat(childRemote, &remoteInfo, error);
            const bool remoteExists = remoteStat == LSCP_SFTP_STAT_EXISTS;

            if (flags.newerOnly && remoteExists &&
                (remoteInfo.flags & LSCP_ATTR_ACMODTIME) != 0 &&
                remoteInfo.mtime >= info.mtime)
            {
                continue;
            }
            const bool convertsAscii = WantsAsciiConversion(flags.transferMode, name);
            TransferStage stage;
            if (!ResolveStage(!convertsAscii && !flags.append && Resumes(flags, info.size), true,
                    childRemote, info.size, stage, error))
            {
                Console::Instance().Error(Texts::RemoteError(
                    "inspect the destination of", childRemote, error));
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            if (mConfirm && remoteExists && !stage.continuing && !flags.append)
            {
                ConfirmationResult confirmation = ConfirmDestructiveAction(
                    Texts::Translate("Overwrite remote file '{path}'?", {{"path", childRemote}}));
                if (confirmation != ConfirmationResult::Accepted)
                {
                    if (confirmation == ConfirmationResult::Unavailable)
                    {
                        mErrors++;
                    }
                    continue;
                }
            }
            if (!PrepareStage(stage, error))
            {
                Console::Instance().Error(Texts::RemoteError(
                    "prepare the destination for", childRemote, error));
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }

            unsigned long long size = 0;
            std::string uploadPath = childLocal;
            std::string asciiTemp;
            if (WantsAsciiConversion(flags.transferMode, name))
            {
                if (!MakeCRLFUploadCopy(childLocal, asciiTemp, error))
                {
                    Console::Instance().Error(Texts::LocalError(
                    "convert the line endings", childLocal, error));
                    mErrors++;
                    success = false;
                    if (AbortAfterFileError())
                    {
                        return false;
                    }
                    continue;
                }
                uploadPath = asciiTemp;
            }
            Console::Instance().TransferStart(name, info.size);
            int result = 0;
            if (stage.complete)
            {
                size = info.size;
            }
            else
            {
                result = RemotePut(uploadPath, stage.partPath, flags.permissions,
                    stage.resumeOffset, flags.preserveTime, &size,
                    ProgressCallback, NULL, error, flags.append);
            }
            Console::Instance().TransferEnd(result == 0);
            if (!asciiTemp.empty())
            {
                remove(asciiTemp.c_str());
            }
            if (result != 0)
            {
                Console::Instance().Error(Texts::TransferFailed(childLocal, error));
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            if (!FinishStage(stage, error))
            {
                Console::Instance().Error(error);
                mErrors++;
                success = false;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            bytesTransferred += size;
            Console::Instance().Status(Texts::FileTransferred(childLocal, size));
            if (flags.deleteSource)
            {
                RemoveLocalFile(childLocal, error);
            }
        }
    }

    /*
     * 'synchronize -delete': remove the remote target entries that the
     * local source does not have. The source files stay where they are.
     */
    if (flags.deleteObsolete)
    {
        LscpNames * remoteNames = NULL;
        std::string listError;
        if (!RemoteListDir(remoteDir, remoteNames, listError))
        {
            Console::Instance().Error(Texts::RemoteError("read directory", remoteDir,
                listError));
            mErrors++;
            return false;
        }
        for (int i = 0; i < remoteNames->count; i++)
        {
            const char * rawName = remoteNames->names[i].filename;
            if (rawName == NULL)
            {
                continue;
            }
            const std::string name(rawName);
            if (name == "." || name == ".." ||
                StringListContains(entries, name))
            {
                continue;
            }
            const std::string obsolete = JoinRemotePath(remoteDir, name);
            const bool obsoleteIsDir =
                (remoteNames->names[i].attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
                (remoteNames->names[i].attrs.permissions & 0040000) != 0;
            const std::string obsoleteRel = relPrefix.empty() ?
                name : relPrefix + "/" + name;
            const unsigned long long obsoleteSize =
                (remoteNames->names[i].attrs.flags & LSCP_ATTR_SIZE) != 0 ?
                remoteNames->names[i].attrs.size : 0;
            const unsigned long obsoleteMtime =
                (remoteNames->names[i].attrs.flags & LSCP_ATTR_ACMODTIME) != 0 ?
                remoteNames->names[i].attrs.mtime : 0;
            if (!flags.mask.empty() &&
                !flags.mask.Accepts(name, obsoleteIsDir, obsoleteSize,
                    obsoleteMtime, obsoleteRel))
            {
                continue;
            }
            if (!ConfirmObsolete("remote", obsolete, obsoleteIsDir))
            {
                success = false;
                continue;
            }
            if (!RemoveRemoteItemRecursive(obsolete))
            {
                success = false;
            }
        }
        RemoteFreeNames(remoteNames);
    }

    /* '-preservetime=all' on an upload: see the download for the why. */
    if (success && flags.preserveTimeDirs && flags.preserveTime)
    {
        const LocalFileInfo info = StatLocal(localDir);
        if (info.exists && info.mtime != 0)
        {
            std::string timeError;
            if (RemoteSetTimes(remoteDir, info.atime != 0 ? info.atime : info.mtime,
                info.mtime, timeError) != 0 && !timeError.empty())
            {
                Console::Instance().Status(Texts::Translate(
                    "Could not set the timestamps of '{path}': {reason}",
                    {{"path", remoteDir}, {"reason", timeError}}));
            }
        }
    }
    return success;
}

/* Every rejection of a transfer switch says the same thing in the same
 * place, so that no path forgets to count the error. */
bool Script::SwitchError(const std::string & command, const std::string & hint)
{
    Console::Instance().Error(Texts::WrongArguments(command, hint));
    mErrors++;
    return false;
}

bool Script::CheckNameOperands(const std::string & command,
    const std::vector<std::string> & args, size_t first)
{
    for (size_t i = first; i < args.size(); i++)
    {
        /* A single '-' is a file name, not a switch, and '--' is not
         * special either: the transfer commands read it the same way. */
        if (args[i].size() < 2 || args[i][0] != '-')
        {
            continue;
        }
        return SwitchError(command, Texts::Translate(
            "Unsupported switch '{switch}'; it will not be ignored. "
            "Prefix a filename beginning with '-' with './'.",
            {{"switch", args[i]}}));
    }
    return true;
}

/*
 * The parameters of this run, expanded exactly as the upstream console
 * expands them, before the line is split into words.
 */
bool Script::ExpandParameters(const std::string & line, std::string & expanded)
{
    std::string error;
    if (ExpandScriptParameters(line, mParameters, expanded, error))
    {
        return true;
    }
    Console::Instance().Error(error);
    mErrors++;
    return false;
}

/*
 * 'synch' means 'synchronize' upstream; 'co' is refused because it could be
 * 'close' or 'command'. A name that matches nothing is reported by the
 * caller, which knows whether an unknown command or an unknown option is
 * the worse mistake.
 */
bool Script::ResolveAbbreviation(const std::vector<std::string> & names,
    const std::string & typed, const std::string & what,
    std::string & resolved)
{
    resolved.clear();
    std::string matches;
    const int index = FindPrefixedName(names, typed, matches);
    if (index == kNameAmbiguous)
    {
        Console::Instance().Error(Texts::WrongArguments(typed,
            Texts::Translate(
                "The {what} '{name}' is ambiguous: it matches {matches}. "
                "Type them out in full.",
                {{"what", what}, {"name", typed}, {"matches", matches}})));
        mErrors++;
        return false;
    }
    if (index >= 0)
    {
        resolved = names[static_cast<size_t>(index)];
    }
    return true;
}

namespace {

/* The vocabularies an abbreviated name is resolved against. */
const std::vector<std::string> & OptionNames()
{
    static const std::vector<std::string> names = {
        "echo", "batch", "confirm", "resume", "transfer", "include",
        "exclude", "failonnomatch", "synchdelete", "reconnecttime",
        "editor", "editmaxsize", "preset"
    };
    return names;
}

const std::vector<std::string> & ToggleNames()
{
    static const std::vector<std::string> names = { "off", "on" };
    return names;
}

/* The values of 'option resume', the persistent setting: 'automatic' is
 * upstream's default (resume binary files from a threshold on). */
const std::vector<std::string> & ResumeModeNames()
{
    static const std::vector<std::string> names = {
        "off", "on", "automatic"
    };
    return names;
}

const std::vector<std::string> & BatchModeNames()
{
    static const std::vector<std::string> names = {
        "off", "on", "abort", "continue"
    };
    return names;
}

const std::vector<std::string> & TransferModeNames()
{
    static const std::vector<std::string> names = {
        "binary", "ascii", "automatic"
    };
    return names;
}

/*
 * A transfer mode, abbreviated the way upstream abbreviates everything else.
 * 'matches' receives the candidates when the text fits more than one mode, so
 * that the caller can say which ones it could have meant.
 */
bool ParseTransferModeName(const std::string & text, TransferMode & mode,
    std::string & matches)
{
    matches.clear();
    const std::string resolved = ResolvePrefixedName(TransferModeNames(),
        ToLower(text), matches);
    if (!matches.empty() || resolved.empty())
    {
        return false;
    }
    return ParseTransferMode(resolved, mode);
}

} // namespace

/*
 * Whether one file of this size is resumed - and therefore transferred
 * through the '.filepart' staging name. '-resumesupport=' is the
 * authoritative switch when it is given: 'off' never resumes, 'on' always
 * does, and a size in kilobytes resumes only the files at least that big
 * (the upstream 'smart' setting). Without it, '-resume' and
 * 'option resume' decide: '-resume' always resumes, and 'option resume'
 * is upstream's persistent setting - 'on' always, 'off' never, and the
 * default 'automatic' resumes binary files from upstream's default
 * threshold of 100 KB on (rsSmart).
 *
 * An ASCII transfer is never resumed by the size threshold: converting line
 * endings changes the byte count, so there is no offset to continue from.
 */
bool Script::Resumes(const TransferFlags & flags, unsigned long long size) const
{
    switch (flags.resumeSupport)
    {
        case TransferFlags::ResumeOff:
            return false;
        case TransferFlags::ResumeOn:
            return true;
        case TransferFlags::ResumeSmart:
            return flags.transferMode == TransferMode::Binary &&
                size >= flags.resumeThreshold;
        case TransferFlags::ResumeUnset:
        default:
            break;
    }
    if (flags.resume)
    {
        return true;
    }
    switch (mResumeMode)
    {
        case ResumeMode::On:
            return true;
        case ResumeMode::Off:
            return false;
        case ResumeMode::Automatic:
        default:
            break;
    }
    return flags.transferMode == TransferMode::Binary &&
        size >= kDefaultResumeThreshold;
}

/*
 * The '.filepart' staging of one transfer, the policy upstream applies
 * whenever a transfer is resume-capable (SftpFileSystem's ResumeAllowed):
 * the bytes go to '<final>.filepart' and are moved onto '<final>' only
 * when the file is complete. A transfer that is interrupted therefore
 * never leaves a truncated file under the final name, and the next
 * resume-capable attempt continues from the staging file - never from
 * the final file, whose existing content may be an unrelated complete
 * version that must not be spliced with new bytes.
 */
bool Script::TransportContinues() const
{
    return !UseNativeScp(mSession.Options().protocol);
}

bool Script::ResolveStage(bool eligible, bool upload,
    const std::string & finalPath, unsigned long long totalSize,
    TransferStage & stage, std::string & error,
    const std::string & stageSuffix)
{
    error.clear();
    stage = TransferStage();
    stage.finalPath = finalPath;
    stage.upload = upload;

    /* Upstream refuses to resume a name that could not carry the suffix
     * (a 255-byte limit on the file name itself); such a file transfers
     * directly instead of failing. A path that ends in a separator cannot
     * name a file to stage either. */
    const std::string baseName = upload ?
        RemoteFileName(finalPath) : LocalFileName(finalPath);
    const std::string effectiveSuffix = stageSuffix.empty() ?
        std::string(kPartialExt) : stageSuffix;
    if (baseName.size() + effectiveSuffix.size() > 255 ||
        (!finalPath.empty() && finalPath[finalPath.size() - 1] == '/'))
    {
        eligible = false;
    }

    if (!eligible)
    {
        stage.partPath = finalPath;
        return true;
    }

    stage.staged = true;
    stage.partPath = finalPath + effectiveSuffix;

    unsigned long long partSize = 0;
    bool partExists = false;
    bool sizeKnown = true;
    if (upload)
    {
        LscpAttrs attrs = {};
        const int statResult = RemoteStat(stage.partPath, &attrs, error);
        if (statResult == LSCP_SFTP_STAT_ERROR)
        {
            return false;
        }
        partExists = statResult == LSCP_SFTP_STAT_EXISTS &&
            (attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
            (attrs.permissions & 0040000) == 0;
        if (partExists)
        {
            sizeKnown = (attrs.flags & LSCP_ATTR_SIZE) != 0;
            partSize = sizeKnown ? attrs.size : 0;
        }
    }
    else
    {
        const LocalFileInfo info = StatLocal(stage.partPath);
        if (info.exists && !info.isRegular)
        {
            /* Something that is not a regular file sits in the staging
             * name; PrepareStage reports it when the transfer gets there. */
            stage.stale = true;
            return true;
        }
        if (!info.exists && info.error != ENOENT && info.error != ENOTDIR)
        {
            error = strerror(info.error);
            return false;
        }
        partExists = info.exists;
        partSize = info.size;
    }

    if (!partExists)
    {
        error.clear(); /* no staging file yet: a missing one is not an error */
        return true; /* fresh transfer into the staging name */
    }
    if (!TransportContinues())
    {
        /*
         * The transport cannot position a write, so it cannot continue
         * this file either: the staging file of an interrupted transfer is
         * discarded and the transfer starts again. Splicing new bytes onto
         * a partial file nobody can vouch for is how a truncated file
         * becomes a corrupt one that looks complete.
         */
        stage.stale = true;
        return true;
    }
    if (!sizeKnown)
    {
        /* Without a size there is no offset to continue from. */
        stage.stale = true;
        return true;
    }
    if (partSize < totalSize)
    {
        stage.continuing = true;
        stage.resumeOffset = partSize;
        Console::Instance().Status(upload ?
            Texts::Translate("Resuming upload of '{path}' from byte {offset}",
                {{"path", baseName}, {"offset", std::to_string(partSize)}}) :
            Texts::Translate("Resuming download of '{path}' from byte {offset}",
                {{"path", baseName}, {"offset", std::to_string(partSize)}}));
        return true;
    }
    if (partSize == totalSize)
    {
        /* Everything is already there; only the move is left. */
        stage.complete = true;
        return true;
    }
    /* Bigger than the source: unusable, and not something to trust. */
    stage.stale = true;
    return true;
}

bool Script::PrepareStage(TransferStage & stage, std::string & error)
{
    error.clear();
    if (!stage.staged || !stage.stale)
    {
        return true;
    }
    int result = 0;
    if (stage.upload)
    {
        result = RemoteRemove(stage.partPath, error);
    }
    else
    {
        result = remove(stage.partPath.c_str());
        if (result != 0)
        {
            error = LastSystemError();
        }
    }
    if (result != 0)
    {
        error = Texts::Translate(
            "Cannot remove the incomplete staging file '{path}': {reason}",
            {{"path", stage.partPath}, {"reason", error}});
        return false;
    }
    stage.stale = false;
    return true;
}

bool Script::FinishStage(const TransferStage & stage, std::string & error)
{
    error.clear();
    if (!stage.staged || stage.partPath == stage.finalPath)
    {
        return true;
    }

    if (!stage.upload)
    {
        if (rename(stage.partPath.c_str(), stage.finalPath.c_str()) != 0)
        {
            error = LastSystemError();
            error = Texts::Translate(
                "The transfer completed, but '{path}' could not be put in "
                "place ({reason}); the complete file is at '{part}'.",
                {{"path", stage.finalPath}, {"reason", error},
                {"part", stage.partPath}});
            return false;
        }
        return true;
    }

    /* Remote: not every protocol's rename replaces an existing
     * destination, so the destination is removed first. The complete
     * data stays in the staging file until this succeeds. */
    LscpAttrs attrs = {};
    std::string statError;
    const int statResult = RemoteStat(stage.finalPath, &attrs, statError);
    if (statResult == LSCP_SFTP_STAT_ERROR)
    {
        error = Texts::Translate(
            "The transfer completed, but '{path}' could not be inspected "
            "for the final move ({reason}); the complete file is at "
            "'{part}'.",
            {{"path", stage.finalPath}, {"reason", statError},
            {"part", stage.partPath}});
        return false;
    }
    if (statResult == LSCP_SFTP_STAT_EXISTS &&
        ToLower(mSession.Options().protocol) != "s3")
    {
        /* S3 CopyObject replaces the current object by creating a new
         * version. Deleting first would insert an unnecessary delete marker
         * between the old and new versions. */
        std::string removeError;
        if (RemoteRemove(stage.finalPath, removeError) != 0)
        {
            error = Texts::Translate(
                "The transfer completed, but '{path}' could not be replaced "
                "({reason}); the complete file is at '{part}'.",
                {{"path", stage.finalPath}, {"reason", removeError},
                {"part", stage.partPath}});
            return false;
        }
    }
    std::string renameError;
    if (RemoteRename(stage.partPath, stage.finalPath, renameError) != 0)
    {
        error = Texts::Translate(
            "The transfer completed, but '{path}' could not be put in "
            "place ({reason}); the complete file is at '{part}'.",
            {{"path", stage.finalPath}, {"reason", renameError},
            {"part", stage.partPath}});
        return false;
    }
    return true;
}

/*
 * Reads the switches of 'get' and 'put' into 'flags' and collects the file
 * names in 'paths'. Anything it does not understand is reported here, before
 * a connection is opened or a file is touched, so that a switch is never
 * silently ignored: a script that asks for a setting this client cannot
 * honour must fail rather than transfer something else.
 */
namespace {

bool RawBool(const std::string & text, bool & value)
{
    std::string v = ToLower(text);
    if (v == "1" || v == "true" || v == "on" || v == "yes")
    {
        value = true;
        return true;
    }
    if (v == "0" || v == "false" || v == "off" || v == "no")
    {
        value = false;
        return true;
    }
    return false;
}

bool RawInteger(const std::string & text, long long & value)
{
    if (text.empty() || isspace(static_cast<unsigned char>(text[0])))
    {
        return false;
    }
    errno = 0;
    char * end = NULL;
    const long long parsed = strtoll(text.c_str(), &end, 10);
    if (errno != 0 || end == NULL || *end != '\0')
    {
        return false;
    }
    value = parsed;
    return true;
}

/*
 * One key=value pair of '-rawtransfersettings', in upstream's own key
 * names (TCopyParamType::Load). Settings this client does not have are
 * refused by name rather than silently dropped: a transfer that ran
 * with less than its script asked for would be worse than one that
 * stopped.
 */
bool ApplyRawTransferSetting(const std::string & rawKey,
    const std::string & value, TransferFlags & flags, std::string & error)
{
    const std::string key = ToLower(rawKey);
    error.clear();
    if (key == "transfermode")
    {
        long long mode = 0;
        if (!RawInteger(value, mode) || mode < 0 || mode > 2)
        {
            error = Texts::Translate(
                "The raw transfer setting 'TransferMode' must be 0 (binary), "
                "1 (ascii) or 2 (automatic).");
            return false;
        }
        flags.transferMode = mode == 0 ? TransferMode::Binary :
            mode == 1 ? TransferMode::Ascii : TransferMode::Automatic;
        return true;
    }
    if (key == "preservetime" || key == "preservetimedirs" ||
        key == "neweronly")
    {
        bool on = false;
        if (!RawBool(value, on))
        {
            error = Texts::Translate(
                "The raw transfer setting '{name}' must be 1 or 0.",
                {{"name", rawKey}});
            return false;
        }
        if (key == "preservetime")
        {
            flags.preserveTime = on;
        }
        else if (key == "preservetimedirs")
        {
            flags.preserveTimeDirs = on;
        }
        else
        {
            flags.newerOnly = on;
        }
        return true;
    }
    if (key == "resumesupport")
    {
        long long mode = 0;
        if (!RawInteger(value, mode) || mode < 0 || mode > 2)
        {
            error = Texts::Translate(
                "The raw transfer setting 'ResumeSupport' must be 0 (on), "
                "1 (smart) or 2 (off).");
            return false;
        }
        flags.resumeSupport = mode == 0 ? TransferFlags::ResumeOn :
            mode == 1 ? TransferFlags::ResumeSmart : TransferFlags::ResumeOff;
        return true;
    }
    if (key == "resumethreshold")
    {
        long long bytes = 0;
        if (!RawInteger(value, bytes) || bytes < 0)
        {
            error = Texts::Translate(
                "The raw transfer setting 'ResumeThreshold' must be a number "
                "of bytes.");
            return false;
        }
        flags.resumeThreshold = static_cast<unsigned long long>(bytes);
        return true;
    }
    if (key == "cpslimit")
    {
        /* Upstream counts bytes per second, this client's -speed= counts
         * kibibytes; round up so the effective limit is never higher. */
        long long cps = 0;
        if (!RawInteger(value, cps) || cps < 0)
        {
            error = Texts::Translate(
                "The raw transfer setting 'CPSLimit' must be a number of "
                "bytes per second.");
            return false;
        }
        flags.speedKBytesPerSecond = static_cast<unsigned>((cps + 1023) / 1024);
        return true;
    }
    if (key == "preserverights" || key == "text")
    {
        if (key == "preserverights")
        {
            bool on = false;
            if (!RawBool(value, on))
            {
                error = Texts::Translate(
                    "The raw transfer setting 'PreserveRights' must be 1 or "
                    "0.");
                return false;
            }
            if (!on)
            {
                flags.permissions = -1;
            }
            else if (flags.permissions == -1)
            {
                /* 'Text' carries the mode this build applies when it is
                 * parsed after this flag; without it the transfer keeps
                 * the default, as upstream does with an empty text. */
            }
            return true;
        }
        /* 'Text': the octal mode rights text. Upstream also accepts a
         * symbolic form here; this build applies what it can parse. */
        unsigned long mode = 0;
        std::string modeError;
        if (!ParsePermissions(value, 0644, false, mode, modeError))
        {
            error = Texts::Translate(
                "The raw transfer setting 'Text' is not a permission mode: "
                "{reason}", {{"reason", modeError}});
            return false;
        }
        flags.permissions = static_cast<int>(mode & 07777);
        return true;
    }
    static const char * refused[] = {
        "masks", "includefilemask", "excludefilemask", "negativeexclude",
        "filenamecase", "preservereadonly", "ignorepermerrors",
        "addxtodirectories", "cleararchive", "removectrlz", "removebom",
        "replaceinvalidchars", "localinvalidchars", "calculatesize",
        "encryptnewfiles", "excludehiddenfiles", "excludeemptydirectories",
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
    {
        if (key == refused[i])
        {
            error = Texts::Translate(
                "The raw transfer setting '{name}' has no equivalent in this "
                "build and will not be ignored.", {{"name", rawKey}});
            return false;
        }
    }
    error = Texts::Translate(
        "The raw transfer setting '{name}' is not known to this build; the "
        "settings it accepts are TransferMode, PreserveTime, "
        "PreserveTimeDirs, ResumeSupport, ResumeThreshold, CPSLimit, "
        "NewerOnly, PreserveRights and Text.", {{"name", rawKey}});
    return false;
}

} // namespace

/*
 * The active preset - a name from 'option preset', from the stored
 * site, or the first preset whose host/user/directory rule matches
 * this connection - provides the base settings of a transfer.
 */
bool Script::ApplySessionPreset(TransferFlags & flags, std::string & error)
{
    error.clear();
    if (mPresetOff)
    {
        /* 'option preset off' is an explicit "use no preset", which also
         * silences the host/user/directory rules until a preset is
         * picked again. */
        return true;
    }
    std::string loadError;
    if (!mPresets.Load(loadError))
    {
        error = loadError;
        return false;
    }
    const TransferPreset * preset = NULL;
    if (!mActivePresetName.empty())
    {
        preset = mPresets.Find(mActivePresetName);
        if (preset == NULL)
        {
            error = Texts::Translate(
                "The transfer preset '{name}' does not exist in '{path}' any "
                "more; pick another with 'option preset <name>' or clear it "
                "with 'option preset off'.",
                {{"name", mActivePresetName}, {"path", mPresets.Path()}});
            return false;
        }
    }
    else
    {
        std::string dirError;
        const std::string localDirectory = GetLocalDirectory(dirError);
        const SessionOptions & options = mSession.Options();
        preset = mPresets.MatchSession(options.hostName, options.userName,
            mRemoteDirectory, localDirectory);
    }
    if (preset != NULL)
    {
        preset->ApplyTo(flags);
    }
    return true;
}

/*
 * The first mask preset accepting this file, applied over the base
 * settings but never over a setting this command's own switches pinned.
 * Speed limits stay command-wide, so a mask preset's speed is applied
 * through the session preset only.
 */
void Script::ApplyMaskPreset(const std::string & fileName, TransferFlags & flags)
{
    if (mPresetOff)
    {
        return;
    }
    if ((flags.explicitSettings & 31) == 31)
    {
        return;
    }
    std::string loadError;
    if (!mPresets.Load(loadError))
    {
        return;
    }
    const TransferPreset * preset = mPresets.MatchMask(fileName);
    if (preset == NULL)
    {
        return;
    }
    /* Copy, clear the pinned bits, apply, restore: ApplyTo writes whole
     * fields, so a preset field is skipped exactly where a switch
     * pinned it. */
    TransferPreset masked = *preset;
    if (flags.explicitSettings & 1) masked.transferMode = -1;
    if (flags.explicitSettings & 2)
    {
        masked.preserveTime = -1;
        masked.preserveTimeDirs = -1;
    }
    if (flags.explicitSettings & 4) masked.newerOnly = -1;
    if (flags.explicitSettings & 8)
    {
        masked.resumeSupport = -1;
        masked.resumeThreshold = -1;
    }
    if (flags.explicitSettings & 16) masked.permissions = -3;
    masked.speedLimit = -1;
    masked.ApplyTo(flags);
}

bool Script::ParseTransferSwitches(const std::string & command, bool uploads,
    const std::vector<std::string> & args, TransferFlags & flags,
    std::vector<std::string> & paths)
{
    /* Resuming needs stable byte offsets, so a switch that asks for it
     * outright cannot be combined with an ASCII/automatic transfer,
     * whichever way the mode was set. */
    bool resumeForced = mResumeMode == ResumeMode::On;
    TransferMode mode = mTransferMode;

    /* The active transfer preset provides the base settings; the
     * switches below then override them one by one. */
    {
        std::string presetError;
        if (!ApplySessionPreset(flags, presetError))
        {
            return SwitchError(command, presetError);
        }
        mode = flags.transferMode;
        if (flags.resumeSupport == TransferFlags::ResumeOn)
        {
            resumeForced = true;
        }
    }

    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string & a = args[i];
        if (a.empty() || a[0] != '-')
        {
            paths.push_back(a);
            continue;
        }
        if (a == "-delete" || a == "-r" || a == "-resume" ||
            a == "-neweronly" || a == "-noneweronly" || a == "-preservetime" ||
            a == "-nopreservetime" || a == "-append" || a == "-nopermissions" ||
            a == "-permissions" || a == "-latest")
        {
            if (a == "-delete")
            {
                flags.deleteSource = true;
            }
            else if (a == "-latest")
            {
                /* Transfer only the newest file the command selected,
                 * which is upstream's '-latest' for get and put. */
                flags.latest = true;
            }
            else if (a == "-neweronly")
            {
                flags.newerOnly = true;
                flags.explicitSettings |= 4;
            }
            else if (a == "-noneweronly")
            {
                flags.newerOnly = false;
                flags.explicitSettings |= 4;
            }
            else if (a == "-preservetime")
            {
                flags.preserveTime = true;
                flags.explicitSettings |= 2;
            }
            else if (a == "-nopreservetime")
            {
                flags.preserveTime = false;
                flags.preserveTimeDirs = false;
                flags.explicitSettings |= 2;
            }
            else if (a == "-append")
            {
                flags.append = true;
            }
            else if (a == "-resume")
            {
                flags.resume = true;
                resumeForced = true;
                flags.explicitSettings |= 8;
            }
            else if (a == "-nopermissions")
            {
                flags.permissions = -1;
                flags.explicitSettings |= 16;
            }
            else if (a == "-permissions")
            {
                /* Without a value: uploads keep the local file's own
                 * mode on the server, downloads give the local file the
                 * remote one. */
                flags.permissions = -2;
                flags.explicitSettings |= 16;
            }
            continue;
        }
        if (a == "-rawtransfersettings" ||
            StartsWith(a, "-rawtransfersettings="))
        {
            /* Upstream's bulk form: key=value parameters under
             * upstream's own key names (TransferMode, PreserveTime,
             * ResumeSupport, ...). The optional '=N' caps how many
             * parameters belong to the switch, upstream's idiom for
             * switches that take a list; uncapped, the parameters are
             * taken while they look like settings. */
            int cap = -1;
            if (StartsWith(a, "-rawtransfersettings="))
            {
                const std::string count =
                    a.substr(strlen("-rawtransfersettings="));
                char * end = NULL;
                const long parsed = count.empty() ? -1 :
                    strtol(count.c_str(), &end, 10);
                if (end == NULL || *end != '\0' || parsed < 0 ||
                    static_cast<long>(static_cast<int>(parsed)) != parsed)
                {
                    return SwitchError(command, Texts::Translate(
                        "The value of '-rawtransfersettings' is the number of settings "
                        "that follow it, as in '-rawtransfersettings=2'."));
                }
                cap = static_cast<int>(parsed);
            }
            int taken = 0;
            while (i + 1 < args.size() && (cap < 0 || taken < cap))
            {
                const std::string & next = args[i + 1];
                if (next.empty() || next[0] == '-' ||
                    next.find('=') == std::string::npos)
                {
                    if (cap < 0)
                    {
                        break;
                    }
                    return SwitchError(command, Texts::Translate("'{name}' is not a 'key=value' raw transfer setting.",
                        {{"name", next}}));
                }
                const size_t eq = next.find('=');
                std::string rawError;
                if (!ApplyRawTransferSetting(next.substr(0, eq),
                    next.substr(eq + 1), flags, rawError))
                {
                    return SwitchError(command, rawError);
                }
                i++;
                taken++;
            }
            if (cap >= 0 && taken < cap)
            {
                return SwitchError(command, Texts::Translate(
                    "'-rawtransfersettings={count}' was given, but only "
                    "{taken} setting parameter(s) follow.",
                    {{"count", std::to_string(cap)},
                    {"taken", std::to_string(taken)}}));
            }
            continue;
        }
        if (StartsWith(a, "-preservetime="))
        {
            /* Upstream takes 'all' to preserve the time of the transferred
             * directories as well as of their files. */
            const std::string value = ToLower(a.substr(strlen("-preservetime=")));
            if (value != "all")
            {
                return SwitchError(command, Texts::Translate(
                    "The only value of '-preservetime' is 'all' (directories are "
                    "timed too); use '-nopreservetime' to keep no timestamps."));
            }
            flags.preserveTime = true;
            flags.preserveTimeDirs = true;
            flags.explicitSettings |= 2;
            continue;
        }
        if (StartsWith(a, "-transfer="))
        {
            std::string matches;
            if (!ParseTransferModeName(a.substr(strlen("-transfer=")), mode,
                matches))
            {
                return SwitchError(command, matches.empty() ?
                                    Texts::Translate(
                                        "The value of '-transfer' must be binary, ascii or "
                                        "automatic.") :
                                    Texts::Translate(
                                        "The value '{value}' of '-transfer' is ambiguous: it "
                                        "matches {matches}.",
                                        {{"value", a.substr(strlen("-transfer="))},
                                        {"matches", matches}}));
            }
            flags.transferMode = mode;
            flags.explicitSettings |= 1;
            continue;
        }
        if (StartsWith(a, "-filemask="))
        {
            std::string maskError;
            if (!flags.mask.Parse(a.substr(strlen("-filemask=")), maskError))
            {
                return SwitchError(command, maskError);
            }
            flags.maskGiven = true;
            continue;
        }
        if (StartsWith(a, "-permissions="))
        {
            unsigned long permissions = 0;
            if (!ParseOctalPermissions(a.substr(strlen("-permissions=")),
                permissions))
            {
                return SwitchError(command, Texts::Translate(
                    "The value of '-permissions' must be an octal number from 0 "
                    "through 7777."));
            }
            flags.permissions = static_cast<int>(permissions);
            flags.explicitSettings |= 16;
            continue;
        }
        if (StartsWith(a, "-speed="))
        {
            /* Like upstream, the value is a number of kibibytes per second
             * and an empty or negative one means no limit at all. */
            const std::string value = a.substr(strlen("-speed="));
            if (value.empty())
            {
                flags.speedKBytesPerSecond = 0;
                continue;
            }
            char * end = NULL;
            const long limit = strtol(value.c_str(), &end, 10);
            /* A value strtol() saturated, or one wider than the field it
             * is stored in, would have been truncated into a different
             * limit than the one the switch asked for. */
            if (end == NULL || *end != '\0' || limit < 0 ||
                limit > static_cast<long>(UINT_MAX))
            {
                return SwitchError(command, Texts::Translate(
                    "The value of '-speed' must be a whole number of kilobytes per "
                    "second (0 removes the limit)."));
            }
            flags.speedKBytesPerSecond = static_cast<unsigned>(limit);
            continue;
        }
        if (a == "-versionid=" || StartsWith(a, "-versionid="))
        {
            if (uploads)
            {
                return SwitchError(command, Texts::Translate(
                    "'-versionid' is available only for S3 downloads."));
            }
            if (flags.versionIdGiven)
            {
                return SwitchError(command, Texts::Translate(
                    "Give '-versionid' only once."));
            }
            flags.versionId = a.substr(strlen("-versionid="));
            if (flags.versionId.empty())
            {
                return SwitchError(command, Texts::Translate(
                    "The value of '-versionid' cannot be empty."));
            }
            flags.versionIdGiven = true;
            continue;
        }
        if (StartsWith(a, "-resumesupport="))
        {
            const std::string value = ToLower(a.substr(strlen("-resumesupport=")));
            if (value == "off" || value == "on")
            {
                flags.resumeSupport = value == "off" ? TransferFlags::ResumeOff :
                    TransferFlags::ResumeOn;
            }
            else
            {
                char * end = NULL;
                const long threshold = strtol(value.c_str(), &end, 10);
                /* The threshold becomes a number of bytes, so a value that
                 * does not survive the multiplication is refused rather
                 * than wrapped into a smaller one. */
                if (end == NULL || *end != '\0' || threshold < 0 ||
                    static_cast<unsigned long long>(threshold) >
                        ULLONG_MAX / 1024ULL)
                {
                    return SwitchError(command, Texts::Translate(
                        "The value of '-resumesupport' must be on, off or a number of "
                        "kilobytes a file must reach to be resumed."));
                }
                flags.resumeSupport = TransferFlags::ResumeSmart;
                flags.resumeThreshold =
                    static_cast<unsigned long long>(threshold) * 1024ULL;
            }
            resumeForced = flags.resumeSupport == TransferFlags::ResumeOn;
            flags.explicitSettings |= 8;
            continue;
        }
        return SwitchError(command, Texts::Translate(
            "Unsupported switch '{switch}'; it will not be ignored. "
            "Prefix a filename beginning with '-' with './'.",
            {{"switch", a}}));
    }

    if (flags.append && flags.resume)
    {
        return SwitchError(command, Texts::Translate(
            "'-append' and '-resume' cannot be used together: one "
            "continues at the end of the destination, the other at a "
            "shared offset in it."));
    }
    if (resumeForced && mode != TransferMode::Binary)
    {
        return SwitchError(command, Texts::Translate(
            "Resuming a transfer is binary only: an ASCII transfer "
            "converts line endings, so byte offsets do not survive."));
    }
    return true;
}

/* The mask a transfer uses: '-filemask=' overrides the persistent
 * 'option include/exclude' mask, and says so. */
void Script::ResolveTransferMask(TransferFlags & flags) const
{
    if (flags.maskGiven)
    {
        if (mOptionMaskUsed)
        {
            Console::Instance().Status(Texts::Translate(
                "The -filemask switch overrides the include/exclude option mask "
                "for this command."));
        }
        return;
    }
    flags.mask = mOptionMask;
}

bool Script::ListLocal(const std::vector<std::string> & args)
{
    if (args.size() > 1)
    {
        Console::Instance().Error(Texts::WrongArguments("lls",
            Texts::Translate("Syntax: lls [<directory>[/<mask>]]")));
        mErrors++;
        return false;
    }
    /* 'lls -l' looked for a file called '-l' and reported "no files found",
     * which reads as an empty directory rather than as a switch this
     * command does not have. */
    if (!CheckNameOperands("lls", args))
    {
        return false;
    }
    std::string error;
    std::string path = args.empty() ? GetLocalDirectory(error) : ExpandTilde(args[0]);
    if (path.empty())
    {
        Console::Instance().Error(error.empty() ?
            std::string("The local directory cannot be determined.") : error);
        mErrors++;
        return false;
    }

    /* Upstream defaults the mask to '*.*' and keeps a trailing wildcard
     * leaf as the mask; both decide what a no-match message says. */
    std::string messageMask = "*.*";
    if (!args.empty())
    {
        const std::string leaf = LocalFileName(path);
        if (HasWildcard(leaf))
        {
            messageMask = leaf;
        }
    }

    std::vector<std::string> paths;
    if (StatLocal(path).isDir)
    {
        std::vector<std::string> names;
        if (!ListLocalDirectory(path, names, error))
        {
            /* Upstream turns any failed search into a no-match line (an
             * error only with failonnomatch), with the OS reason after it. */
            NoMatch(messageMask, error.empty() ?
                std::string("The directory cannot be listed.") : error);
            return true;
        }
        for (const std::string & name : names)
        {
            paths.push_back(JoinLocalPath(path, name));
        }
    }
    else if (!ExpandLocalWildcard(path, paths, error) ||
        (!HasWildcard(path) && paths.empty()))
    {
        NoMatch(messageMask, !error.empty() ? error :
            std::string("No such file or directory."));
        return true;
    }

    std::sort(paths.begin(), paths.end());

    /* The columns of upstream's lls: date, time, size (or <DIR>) and the
     * name, with the date and time widths taken from the widest entry. */
    struct Row
    {
        std::string date;
        std::string time;
        std::string size;
        std::string name;
    };
    std::vector<Row> rows;
    size_t dateLen = 0;
    size_t timeLen = 0;
    for (const std::string & entry : paths)
    {
        const std::string name = LocalFileName(entry);
        if (name == ".")
        {
            continue;
        }
        const LocalFileInfo info = StatLocal(entry);
        Row row;
        row.date = FormatFileDate(info.mtime);
        row.time = FormatFileClock(info.mtime);
        char size[32];
        if (info.isDir)
        {
            snprintf(size, sizeof(size), "%-14s", "<DIR>");
        }
        else
        {
            snprintf(size, sizeof(size), "%14llu",
                static_cast<unsigned long long>(info.size));
        }
        row.size = size;
        row.name = name;
        dateLen = row.date.size() > dateLen ? row.date.size() : dateLen;
        timeLen = row.time.size() > timeLen ? row.time.size() : timeLen;
        rows.push_back(row);
    }
    if (rows.empty())
    {
        NoMatch(messageMask, std::string());
        return true;
    }
    for (const Row & row : rows)
    {
        std::string date = row.date;
        date.append(dateLen - row.date.size(), ' ');
        std::string time = row.time;
        time.append(timeLen - row.time.size(), ' ');
        Console::Instance().WriteLine(date + "  " + time + "    " +
            row.size + " " + row.name);
    }
    return true;
}

bool Script::GetFiles(const std::vector<std::string> & args)
{
    TransferFlags flags;
    flags.transferMode = mTransferMode;
    std::vector<std::string> paths;
    if (!ParseTransferSwitches("get", false, args, flags, paths))
    {
        return false;
    }
    /*
     * Naming the newest object and naming an exact version are two
     * different answers to one question; say so before asking for the
     * connection the rest of the switches may need.
     */
    if (flags.latest && flags.versionIdGiven)
    {
        return SwitchError("get", Texts::Translate(
            "'-latest' cannot be combined with '-versionid': one names the "
            "newest object, the other one exact version."));
    }
    if (!RequireConnection())
    {
        return false;
    }

    const bool versioned = flags.versionIdGiven;
    if (versioned && ToLower(mSession.Options().protocol) != "s3")
    {
        return SwitchError("get", Texts::Translate(
            "'-versionid' is available only for S3 downloads."));
    }
    if (versioned && (flags.deleteSource || flags.append))
    {
        return SwitchError("get", Texts::Translate(
            "'-versionid' cannot be combined with '-delete' or '-append'."));
    }
    if (versioned && (paths.size() > 2 ||
        (!paths.empty() && HasWildcard(paths[0]))))
    {
        return SwitchError("get", Texts::Translate(
            "'-versionid' needs one exact S3 object path and one optional "
            "local destination; wildcards and multiple sources are not "
            "supported."));
    }

    if (paths.empty())
    {
        Console::Instance().Error(Texts::WrongArguments("get",
            Texts::Translate("Syntax: get [switches] <remotefile(s)> [<localpath>]")));
        mErrors++;
        return false;
    }

    /* Only the native transport can write at a position of the local file
     * that is not the offset it read on the remote one. */
    if (flags.append && !UseNativeSftp(mSession.Options().protocol))
    {
        return SwitchError("get", Texts::Translate(
            "'-append' needs the native SFTP transport; the transfer "
            "backends cannot position a write."));
    }
    /*
     * SCP's rcp protocol has no offset to continue from, so a transfer
     * that asks to resume by name is refused instead of quietly starting
     * over: '-resume', '-resumesupport=on' and a '-resumesupport=<KB>'
     * threshold all promise a continuation this transport cannot make.
     * The default 'option resume automatic' is not a promise - it stages
     * the transfer so an interrupted one is not left under the final
     * name, and this engine still does that, renaming '.filepart' into
     * place through the server's shell.
     */
    if (UseNativeScp(mSession.Options().protocol) && (flags.resume ||
        flags.resumeSupport == TransferFlags::ResumeOn ||
        flags.resumeSupport == TransferFlags::ResumeSmart ||
        (flags.resumeSupport == TransferFlags::ResumeUnset &&
         mResumeMode == ResumeMode::On)))
    {
        return SwitchError("get", Texts::Translate(
            "SCP cannot resume a transfer: the rcp protocol has no offset "
            "to continue from, and a partial file nobody can position is "
            "not one to splice bytes onto. Use 'option resume off' or "
            "'-resumesupport=off'."));
    }
    ResolveTransferMask(flags);
    SpeedLimitForThisCommand limiter(flags.speedKBytesPerSecond, &mSpeedLimit);

    /* What every file starts from; a mask preset then adjusts the
     * settings this command's switches did not pin. */
    const TransferFlags baseFlags = flags;

    std::string destination = paths.size() >= 2 ? paths.back() : ".";
    std::vector<std::string> sourcePatterns = paths.size() >= 2 ?
        std::vector<std::string>(paths.begin(), paths.end() - 1) :
        std::vector<std::string>(paths.begin(), paths.end());

    /*
     * '-latest': upstream first builds the whole file list and then keeps
     * the one file with the newest modification time, so a mask and
     * several file parameters compete with one another instead of each
     * choosing its own. The comparison is on the source side, before a
     * mask preset narrows the file.
     */
    if (flags.latest)
    {
        std::string newestPath;
        unsigned long newestTime = 0;
        bool haveNewest = false;
        for (size_t i = 0; i < sourcePatterns.size(); i++)
        {
            std::vector<std::string> expanded;
            std::string error;
            if (!ExpandRemote(sourcePatterns[i], expanded, error))
            {
                Console::Instance().Error(Texts::RemoteError("read",
                    sourcePatterns[i], error));
                mErrors++;
                return false;
            }
            for (size_t n = 0; n < expanded.size(); n++)
            {
                LscpAttrs attrs = {};
                std::string statError;
                if (RemoteStat(expanded[n], &attrs, statError) !=
                    LSCP_SFTP_STAT_EXISTS)
                {
                    continue;
                }
                const unsigned long when =
                    (attrs.flags & LSCP_ATTR_ACMODTIME) != 0 ? attrs.mtime : 0;
                if (!haveNewest || when > newestTime)
                {
                    newestPath = expanded[n];
                    newestTime = when;
                    haveNewest = true;
                }
            }
        }
        if (!haveNewest)
        {
            /* Nothing matched: report it the way the ordinary loop does,
             * and transfer nothing. */
            for (size_t i = 0; i < sourcePatterns.size(); i++)
            {
                if (HasWildcard(sourcePatterns[i]))
                {
                    Console::Instance().Status(Texts::Translate(
                        "No file matching '{pattern}' was found.",
                        {{"pattern", sourcePatterns[i]}}));
                    if (mFailOnNoMatch)
                    {
                        mErrors++;
                    }
                }
                else
                {
                    Console::Instance().Error(Texts::RemoteError("find",
                        sourcePatterns[i], "No such file."));
                    mErrors++;
                }
            }
            return false;
        }
        sourcePatterns.assign(1, newestPath);
    }

    LocalFileInfo destinationInfo = StatLocal(ExpandTilde(destination));
    bool destinationIsDir = destinationInfo.isDir;

    bool any = false;
    for (size_t i = 0; i < sourcePatterns.size(); i++)
    {
        std::vector<std::string> sources;
        std::string error;
        if (versioned)
        {
            sources.push_back(ResolveRemotePath(mRemoteDirectory,
                sourcePatterns[i]));
        }
        else if (!ExpandRemote(sourcePatterns[i], sources, error))
        {
            Console::Instance().Error(Texts::RemoteError("read", sourcePatterns[i], error));
            mErrors++;
            continue;
        }
        if (sources.empty())
        {
            if (HasWildcard(sourcePatterns[i]))
            {
                Console::Instance().Status(Texts::Translate(
                    "No file matching '{pattern}' was found.",
                    {{"pattern", sourcePatterns[i]}}));
                if (mFailOnNoMatch)
                {
                    mErrors++;
                }
                continue;
            }
            Console::Instance().Error(Texts::RemoteError("find", sourcePatterns[i],
                "No such file."));
            mErrors++;
            continue;
        }
        if (sources.size() > 1 || sourcePatterns.size() > 1)
        {
            if (destinationInfo.exists && !destinationInfo.isDir)
            {
                Console::Instance().Error(Texts::LocalError("download", destination,
                    "A directory is required for multiple source files."));
                mErrors++;
                continue;
            }
            if (!destinationIsDir)
            {
                if (!CreateLocalDirectoryRecursive(ExpandTilde(destination), error))
                {
                    Console::Instance().Error(Texts::LocalError("create directory",
                        destination, error));
                    mErrors++;
                    continue;
                }
                destinationIsDir = true;
                destinationInfo = StatLocal(ExpandTilde(destination));
            }
        }
        for (size_t n = 0; n < sources.size(); n++)
        {
            LscpAttrs sourceAttrs = {};
            int statRes = versioned ?
                S3Client::StatVersion(mSession.Options(), sources[n],
                    flags.versionId, &sourceAttrs, error) :
                RemoteStat(sources[n], &sourceAttrs, error);
            if (versioned && statRes != LSCP_SFTP_STAT_EXISTS)
            {
                Console::Instance().Error(Texts::RemoteError("read",
                    sources[n], error.empty() ? "No such object version." : error));
                mErrors++;
                continue;
            }
            bool isDir = (statRes == LSCP_SFTP_STAT_EXISTS) &&
                (sourceAttrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
                (sourceAttrs.permissions & 0040000) != 0;

            /* The file mask applies to the selected names too; a
             * directory itself is filtered by what is inside it. */
            if (!flags.mask.empty() && !isDir &&
                !flags.mask.Accepts(RemoteFileName(sources[n]), false,
                    (sourceAttrs.flags & LSCP_ATTR_SIZE) != 0 ? sourceAttrs.size : 0,
                    (sourceAttrs.flags & LSCP_ATTR_ACMODTIME) != 0 ? sourceAttrs.mtime : 0,
                    RemoteFileName(sources[n])))
            {
                continue;
            }

            if (isDir)
            {
                if (!flags.recursive)
                {
                    Console::Instance().Error(Texts::TransferFailed(sources[n],
                        Texts::Translate(
                            "Directories are not supported without recursive mode.")));
                    mErrors++;
                    continue;
                }
                std::string targetLocalDir = (destinationIsDir || sources.size() > 1 || sourcePatterns.size() > 1) ?
                    JoinLocalPath(ExpandTilde(destination), RemoteFileName(sources[n])) :
                    ExpandTilde(destination);

                unsigned long long dirBytes = 0;
                if (DownloadDirectoryRecursive(sources[n], targetLocalDir, flags, dirBytes))
                {
                    any = true;
                    if (flags.deleteSource)
                    {
                        RemoteRemoveDir(sources[n], error);
                    }
                }
                continue;
            }

            /* This file's own settings: the command's base, overridden
             * by the preset whose mask accepts it (never by settings
             * the switches pinned). */
            flags = baseFlags;
            ApplyMaskPreset(RemoteFileName(sources[n]), flags);

            std::string localPath;
            if (destinationIsDir || sources.size() > 1 || sourcePatterns.size() > 1)
            {
                localPath = JoinLocalPath(ExpandTilde(destination),
                    RemoteFileName(sources[n]));
            }
            else
            {
                localPath = ExpandTilde(destination);
            }

            LocalFileInfo localInfo = StatLocal(localPath);
            if (!localInfo.exists && localInfo.error != ENOENT &&
                localInfo.error != ENOTDIR)
            {
                errno = localInfo.error;
                Console::Instance().Error(Texts::LocalError("inspect the destination",
                    localPath, LastSystemError()));
                mErrors++;
                continue;
            }
            if (localInfo.isDir)
            {
                Console::Instance().Error(Texts::LocalError("download", localPath,
                    "The destination is a directory."));
                mErrors++;
                continue;
            }
            if (localInfo.exists && !localInfo.isRegular)
            {
                Console::Instance().Error(Texts::LocalError("download", localPath,
                    "The destination is not a regular file."));
                mErrors++;
                continue;
            }
            if (flags.newerOnly && localInfo.exists &&
                (sourceAttrs.flags & LSCP_ATTR_ACMODTIME) != 0 &&
                localInfo.mtime >= sourceAttrs.mtime)
            {
                continue;
            }

            unsigned long long totalSize = 0;
            if ((sourceAttrs.flags & LSCP_ATTR_SIZE) != 0)
            {
                totalSize = sourceAttrs.size;
            }
            /* Resolve the '.filepart' staging: read-only, so the
             * confirmation below still runs before anything is removed
             * or written. */
            const bool convertsAscii = WantsAsciiConversion(
                flags.transferMode, RemoteFileName(sources[n]));
            TransferStage stage;
            const std::string stageSuffix = versioned ?
                std::string(".filepart.v") +
                    s3sig::Sha256Hex(flags.versionId) :
                std::string(".filepart");
            if (!ResolveStage(!convertsAscii && !flags.append && Resumes(flags, totalSize), false,
                    localPath, totalSize, stage, error, stageSuffix))
            {
                Console::Instance().Error(Texts::LocalError(
                    "inspect the destination", localPath, error));
                mErrors++;
                continue;
            }
            /* Asking before overwriting protects the complete file that is
             * at the destination now; a continuation of this same transfer
             * and '-append' have been through it already. */
            if (mConfirm && localInfo.exists && !stage.continuing && !flags.append)
            {
                ConfirmationResult confirmation = ConfirmDestructiveAction(
                    Texts::Translate("Overwrite local file '{path}'?", {{"path", localPath}}));
                if (confirmation != ConfirmationResult::Accepted)
                {
                    if (confirmation == ConfirmationResult::Unavailable)
                    {
                        mErrors++;
                    }
                    continue;
                }
            }
            if (!PrepareStage(stage, error))
            {
                Console::Instance().Error(Texts::LocalError(
                    "prepare the destination", localPath, error));
                mErrors++;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }

            unsigned long long size = 0;
            Console::Instance().TransferStart(RemoteFileName(sources[n]), totalSize);
            int result = 0;
            if (stage.complete)
            {
                size = totalSize;
            }
            else
            {
                result = RemoteGet(sources[n], stage.partPath, stage.resumeOffset,
                    flags.preserveTime, &size, ProgressCallback, NULL, error,
                    flags.append, versioned ? flags.versionId : std::string());
            }
            Console::Instance().TransferEnd(result == 0);
            if (result != 0)
            {
                Console::Instance().Error(Texts::TransferFailed(sources[n], error));
                mErrors++;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            if (WantsAsciiConversion(flags.transferMode, RemoteFileName(sources[n])))
            {
                unsigned long long converted = 0;
                if (!ConvertToUnixLineEndings(stage.partPath, converted, error))
                {
                    Console::Instance().Error(Texts::LocalError(
                    "convert the line endings", localPath, error));
                    mErrors++;
                    if (AbortAfterFileError())
                    {
                        return false;
                    }
                    continue;
                }
                size = converted;
            }
            if (flags.preserveTime && (sourceAttrs.flags & LSCP_ATTR_ACMODTIME) != 0)
            {
                SetFileTimes(stage.partPath, sourceAttrs.atime, sourceAttrs.mtime);
            }
            if (!FinishStage(stage, error))
            {
                Console::Instance().Error(error);
                mErrors++;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            /* '-permissions' on a download: give the local file the
             * mode the script asked for, or the remote file's own. */
            if (flags.permissions >= 0 || flags.permissions == -2)
            {
                int localMode = flags.permissions;
                if (localMode == -2)
                {
                    localMode = (sourceAttrs.flags & LSCP_ATTR_PERMISSIONS) != 0 ?
                        static_cast<int>(sourceAttrs.permissions & 07777) : -1;
                }
                if (localMode >= 0 && !SetLocalFileMode(localPath, localMode, error))
                {
                    Console::Instance().Error(Texts::LocalError(
                    "set the permissions", localPath, error));
                    mErrors++;
                }
            }
            any = true;
            Console::Instance().Status(Texts::FileTransferred(localPath, size));
            if (flags.deleteSource)
            {
                RemoteRemove(sources[n], error);
            }
        }
    }
    return any;
}

bool Script::PutFiles(const std::vector<std::string> & args)
{
    TransferFlags flags;
    flags.transferMode = mTransferMode;
    std::vector<std::string> paths;
    if (!ParseTransferSwitches("put", true, args, flags, paths))
    {
        return false;
    }
    if (!RequireConnection())
    {
        return false;
    }

    if (paths.empty())
    {
        Console::Instance().Error(Texts::WrongArguments("put",
            Texts::Translate("Syntax: put [switches] <localfile(s)> [<remotepath>]")));
        mErrors++;
        return false;
    }

    if (flags.append && !UseNativeSftp(mSession.Options().protocol))
    {
        return SwitchError("put", Texts::Translate(
            "'-append' needs the native SFTP transport; the transfer "
            "backends cannot position a write."));
    }
    /*
     * SCP's rcp protocol has no offset to continue from, so a transfer
     * that asks to resume by name is refused instead of quietly starting
     * over: '-resume', '-resumesupport=on' and a '-resumesupport=<KB>'
     * threshold all promise a continuation this transport cannot make.
     * The default 'option resume automatic' is not a promise - it stages
     * the transfer so an interrupted one is not left under the final
     * name, and this engine still does that, renaming '.filepart' into
     * place through the server's shell.
     */
    if (UseNativeScp(mSession.Options().protocol) && (flags.resume ||
        flags.resumeSupport == TransferFlags::ResumeOn ||
        flags.resumeSupport == TransferFlags::ResumeSmart ||
        (flags.resumeSupport == TransferFlags::ResumeUnset &&
         mResumeMode == ResumeMode::On)))
    {
        return SwitchError("put", Texts::Translate(
            "SCP cannot resume a transfer: the rcp protocol has no offset "
            "to continue from, and a partial file nobody can position is "
            "not one to splice bytes onto. Use 'option resume off' or "
            "'-resumesupport=off'."));
    }
    ResolveTransferMask(flags);
    SpeedLimitForThisCommand limiter(flags.speedKBytesPerSecond, &mSpeedLimit);

    /* What every file starts from; a mask preset then adjusts the
     * settings this command's switches did not pin. */
    const TransferFlags baseFlags = flags;

    std::string destinationArg = paths.size() >= 2 ? paths.back() : ".";
    std::vector<std::string> sourcePatterns = paths.size() >= 2 ?
        std::vector<std::string>(paths.begin(), paths.end() - 1) :
        std::vector<std::string>(paths.begin(), paths.end());

    /*
     * '-latest': the newest of everything the command selected, chosen on
     * the local side before the destination is looked at, so that a
     * single file is uploaded under the destination's name instead of
     * the mask's.
     */
    if (flags.latest)
    {
        std::string newestPath;
        unsigned long newestTime = 0;
        bool haveNewest = false;
        std::string localError;
        const std::string current = GetLocalDirectory(localError);
        if (current.empty())
        {
            Console::Instance().Error(localError);
            mErrors++;
            return false;
        }
        for (size_t i = 0; i < sourcePatterns.size(); i++)
        {
            std::vector<std::string> expanded;
            std::string error;
            if (!ExpandLocalWildcard(ResolveLocalPath(current,
                    sourcePatterns[i]), expanded, error))
            {
                Console::Instance().Error(Texts::LocalError(
                    "expand the file name", sourcePatterns[i], error));
                mErrors++;
                return false;
            }
            for (size_t n = 0; n < expanded.size(); n++)
            {
                const LocalFileInfo info = StatLocal(expanded[n]);
                if (!info.exists)
                {
                    continue;
                }
                if (!haveNewest || info.mtime > newestTime)
                {
                    newestPath = expanded[n];
                    newestTime = info.mtime;
                    haveNewest = true;
                }
            }
        }
        if (!haveNewest)
        {
            for (size_t i = 0; i < sourcePatterns.size(); i++)
            {
                if (HasWildcard(sourcePatterns[i]))
                {
                    Console::Instance().Status(Texts::Translate(
                        "No file matching '{pattern}' was found.",
                        {{"pattern", sourcePatterns[i]}}));
                    if (mFailOnNoMatch)
                    {
                        mErrors++;
                    }
                }
                else
                {
                    Console::Instance().Error(Texts::LocalError(
                        "expand the file name", sourcePatterns[i],
                        "No such file."));
                    mErrors++;
                }
            }
            return false;
        }
        sourcePatterns.assign(1, newestPath);
    }

    std::string destination = ResolveRemotePath(mRemoteDirectory, destinationArg);
    LscpAttrs destinationAttrs = {};
    std::string destErr;
    const int destinationStat = RemoteStat(destination, &destinationAttrs, destErr);
    if (destinationStat == LSCP_SFTP_STAT_ERROR)
    {
        Console::Instance().Error(Texts::RemoteError("inspect destination", destination,
            destErr));
        mErrors++;
        return false;
    }
    bool destinationExists = destinationStat == LSCP_SFTP_STAT_EXISTS;
    bool destinationIsDir = destinationExists &&
        (destinationAttrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
        (destinationAttrs.permissions & 0040000) != 0;

    bool any = false;
    for (size_t i = 0; i < sourcePatterns.size(); i++)
    {
        std::vector<std::string> sources;
        std::string error;
        std::string current = GetLocalDirectory(error);
        if (current.empty())
        {
            Console::Instance().Error(error);
            mErrors++;
            continue;
        }
        if (!ExpandLocalWildcard(ResolveLocalPath(current, sourcePatterns[i]), sources, error))
        {
            Console::Instance().Error(Texts::LocalError("expand the file name", sourcePatterns[i], error));
            mErrors++;
            continue;
        }
        if (sources.empty())
        {
            if (HasWildcard(sourcePatterns[i]))
            {
                Console::Instance().Status(Texts::Translate(
                    "No file matching '{pattern}' was found.",
                    {{"pattern", sourcePatterns[i]}}));
                if (mFailOnNoMatch)
                {
                    mErrors++;
                }
                continue;
            }
            Console::Instance().Error(Texts::LocalError("expand the file name", sourcePatterns[i],
                "No such file."));
            mErrors++;
            continue;
        }
        if (sources.size() > 1 || sourcePatterns.size() > 1)
        {
            if (destinationExists && !destinationIsDir)
            {
                Console::Instance().Error(Texts::RemoteError("upload to", destination,
                    "A directory is required for multiple source files."));
                mErrors++;
                continue;
            }
            if (!destinationIsDir)
            {
                if (!CreateRemoteDirectoryRecursive(destination, error))
                {
                    Console::Instance().Error(Texts::RemoteError("create the directory",
                        destination, error));
                    mErrors++;
                    continue;
                }
                destinationExists = true;
                destinationIsDir = true;
            }
        }
        for (size_t n = 0; n < sources.size(); n++)
        {
            LocalFileInfo info = StatLocal(sources[n]);
            if (info.isDir)
            {
                if (!flags.recursive)
                {
                    Console::Instance().Error(Texts::LocalError("upload", sources[n],
                        Texts::Translate(
                            "Directories are not supported without recursive mode.")));
                    mErrors++;
                    continue;
                }
                std::string targetRemoteDir = (destinationIsDir || sources.size() > 1 ||
                    sourcePatterns.size() > 1) ?
                    JoinRemotePath(destination, LocalFileName(sources[n])) : destination;

                unsigned long long dirBytes = 0;
                if (UploadDirectoryRecursive(sources[n], targetRemoteDir, flags, dirBytes))
                {
                    any = true;
                    if (flags.deleteSource)
                    {
                        std::string removeError;
                        RemoveLocalDirectory(sources[n], removeError);
                    }
                }
                continue;
            }
            if (info.exists && !info.isRegular)
            {
                Console::Instance().Error(Texts::LocalError("upload", sources[n],
                    "Only regular files can be uploaded."));
                mErrors++;
                continue;
            }
            /* The file mask applies to the selected names too; a
             * directory is filtered by what is inside it. */
            if (!flags.mask.empty() && !info.isDir &&
                !flags.mask.Accepts(LocalFileName(sources[n]), false,
                    info.size, info.mtime, LocalFileName(sources[n])))
            {
                continue;
            }
            /* This file's own settings: the command's base, overridden
             * by the preset whose mask accepts it (never by settings
             * the switches pinned). */
            flags = baseFlags;
            ApplyMaskPreset(LocalFileName(sources[n]), flags);

            std::string remotePath = (destinationIsDir || sources.size() > 1 ||
                sourcePatterns.size() > 1) ?
                JoinRemotePath(destination, LocalFileName(sources[n])) : destination;
            LscpAttrs remoteInfo = {};
            const int remoteStat = RemoteStat(remotePath, &remoteInfo, error);
            if (remoteStat == LSCP_SFTP_STAT_ERROR)
            {
                Console::Instance().Error(Texts::RemoteError("inspect destination",
                    remotePath, error));
                mErrors++;
                continue;
            }
            const bool remoteExists = remoteStat == LSCP_SFTP_STAT_EXISTS;
            if (remoteExists && (remoteInfo.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
                (remoteInfo.permissions & 0040000) != 0)
            {
                Console::Instance().Error(Texts::RemoteError("upload to", remotePath,
                    "The destination is a directory."));
                mErrors++;
                continue;
            }
            if (flags.newerOnly && remoteExists &&
                (remoteInfo.flags & LSCP_ATTR_ACMODTIME) != 0 &&
                remoteInfo.mtime >= info.mtime)
            {
                continue;
            }
            /* Resolve the '.filepart' staging: read-only, so the
             * confirmation below still runs before anything is removed
             * or written. */
            const bool convertAscii =
                WantsAsciiConversion(flags.transferMode, LocalFileName(sources[n]));
            TransferStage stage;
            if (!ResolveStage(!convertAscii && !flags.append && Resumes(flags, info.size), true,
                    remotePath, info.size, stage, error))
            {
                Console::Instance().Error(Texts::RemoteError(
                    "inspect the destination of", remotePath, error));
                mErrors++;
                continue;
            }
            if (mConfirm && remoteExists && !stage.continuing && !flags.append)
            {
                ConfirmationResult confirmation = ConfirmDestructiveAction(
                    Texts::Translate("Overwrite remote file '{path}'?", {{"path", remotePath}}));
                if (confirmation != ConfirmationResult::Accepted)
                {
                    if (confirmation == ConfirmationResult::Unavailable)
                    {
                        mErrors++;
                    }
                    continue;
                }
            }
            if (!PrepareStage(stage, error))
            {
                Console::Instance().Error(Texts::RemoteError(
                    "prepare the destination for", remotePath, error));
                mErrors++;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            unsigned long long size = 0;
            /* ASCII uploads convert a temporary copy, so the local file
             * is never modified. */
            std::string uploadPath = sources[n];
            std::string asciiTemp;
            if (convertAscii)
            {
                if (!MakeCRLFUploadCopy(sources[n], asciiTemp, error))
                {
                    Console::Instance().Error(Texts::LocalError(
                    "convert the line endings", sources[n], error));
                    mErrors++;
                    if (AbortAfterFileError())
                    {
                        return false;
                    }
                    continue;
                }
                uploadPath = asciiTemp;
            }
            Console::Instance().TransferStart(LocalFileName(sources[n]), info.size);
            int result = 0;
            if (stage.complete)
            {
                size = info.size;
            }
            else
            {
                int putPermissions = flags.permissions;
                if (putPermissions == -2)
                {
                    putPermissions = info.permissions != 0 ?
                        static_cast<int>(info.permissions & 07777) : -1;
                }
                result = RemotePut(uploadPath, stage.partPath, putPermissions,
                    stage.resumeOffset, flags.preserveTime, &size,
                    ProgressCallback, NULL, error, flags.append);
            }
            Console::Instance().TransferEnd(result == 0);
            if (!asciiTemp.empty())
            {
                remove(asciiTemp.c_str());
            }
            if (result != 0)
            {
                Console::Instance().Error(Texts::TransferFailed(sources[n], error));
                mErrors++;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            if (!FinishStage(stage, error))
            {
                Console::Instance().Error(error);
                mErrors++;
                if (AbortAfterFileError())
                {
                    return false;
                }
                continue;
            }
            any = true;
            Console::Instance().Status(Texts::FileTransferred(remotePath, size));
            if (flags.deleteSource)
            {
                RemoveLocalFile(sources[n], error);
            }
        }
    }
    return any;
}

/* ------------------------------------------------------------------ *
 * Synchronization                                                     *
 * ------------------------------------------------------------------ */

namespace {

/* The local side of a synchronization. */
/* Upstream compares the contents of two files with SHA-256 (SHA-1 when a
 * server cannot do SHA-256); this build asks for SHA-256 and falls back to
 * hashing a downloaded copy when the server has no checksum extension. */
const char * const kSyncChecksumAlgorithm = "sha-256";

class LocalSyncFileSystem : public SyncFileSystem
{
public:
    virtual bool ListDirectory(const std::string & path,
        std::vector<SyncEntry> & entries, std::string & error)
    {
        std::vector<std::string> names;
        if (!ListLocalDirectory(path, names, error))
        {
            return false;
        }
        for (size_t i = 0; i < names.size(); i++)
        {
            const LocalFileInfo info = StatLocal(JoinLocalPath(path, names[i]));
            SyncEntry entry;
            entry.name = names[i];
            entry.isDirectory = info.isDir;
            entry.size = info.size;
            entry.mtime = info.mtime;
            entry.permissions = static_cast<unsigned long>(info.permissions);
            entries.push_back(entry);
        }
        return true;
    }

    virtual const char * Label() const { return "local"; }

    virtual bool HashFile(const std::string & path, std::string & hash,
        std::string & error)
    {
        char digest[LSCP_HASH_HEX_SIZE];
        if (lscp_hash_file(kSyncChecksumAlgorithm, path.c_str(), digest,
            sizeof(digest)) != 0)
        {
            error = lscp_hash_error();
            return false;
        }
        hash = digest;
        return true;
    }
};

/* The remote side: whatever protocol this session speaks. */
class RemoteSyncFileSystem : public SyncFileSystem
{
public:
    explicit RemoteSyncFileSystem(Script & script) : mScript(script),
        mNoteShown(false) {}

    virtual bool ListDirectory(const std::string & path,
        std::vector<SyncEntry> & entries, std::string & error)
    {
        return mScript.ListRemoteEntries(path, entries, error);
    }

    virtual const char * Label() const { return "remote"; }

    /* The contents of a remote file, as the checksum the 'checksum' command
     * would print: the server's own when it can, a downloaded copy
     * otherwise. Whatever the two were, the user is told once rather than
     * once per file. */
    virtual bool HashFile(const std::string & path, std::string & hash,
        std::string & error)
    {
        std::string note;
        if (!mScript.RemoteChecksumFile(path, kSyncChecksumAlgorithm, hash,
            note, error))
        {
            return false;
        }
        if (!note.empty() && !mNoteShown)
        {
            mNoteShown = true;
            Console::Instance().Status(note + " Comparing the contents of a "
                "synchronization downloads every file it reaches.");
        }
        return true;
    }

private:
    Script & mScript;
    bool mNoteShown;
};

std::string DescribeTime(unsigned long value)
{
    if (value == 0)
    {
        return "unknown";
    }
    std::tm parts;
    if (!LocalTime(static_cast<std::time_t>(value), parts))
    {
        return "unknown";
    }
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", &parts);
    return std::string(buffer);
}

/* True for a directory that is the root of a file system: deleting
 * "obsolete" entries there is far more likely to be a mistake than a
 * synchronization, so 'synchronize -delete' refuses it. */
bool IsFileSystemRoot(const std::string & path)
{
    std::string trimmed = path;
    while (trimmed.size() > 1 && trimmed[trimmed.size() - 1] == '/')
    {
        trimmed.erase(trimmed.size() - 1);
    }
    return trimmed.empty() || trimmed == "/";
}

} // namespace

bool Script::ListRemoteEntries(const std::string & path,
    std::vector<SyncEntry> & entries, std::string & error)
{
    LscpNames * names = NULL;
    if (!RemoteListDir(path, names, error))
    {
        return false;
    }
    for (int i = 0; i < names->count; i++)
    {
        const char * raw = names->names[i].filename;
        if (raw == NULL)
        {
            continue;
        }
        const std::string name(raw);
        if (name == "." || name == "..")
        {
            continue;
        }
        SyncEntry entry;
        entry.name = name;
        const LscpAttrs & attrs = names->names[i].attrs;
        if ((attrs.flags & LSCP_ATTR_PERMISSIONS) != 0)
        {
            entry.isDirectory = (attrs.permissions & 0040000) != 0;
            entry.permissions = attrs.permissions;
        }
        if ((attrs.flags & LSCP_ATTR_SIZE) != 0)
        {
            entry.size = attrs.size;
        }
        if ((attrs.flags & LSCP_ATTR_ACMODTIME) != 0)
        {
            entry.mtime = attrs.mtime;
        }
        /* A backend that does not report the permissions of a listing
         * (curl) still has to be able to tell a directory from a file. */
        if ((attrs.flags & LSCP_ATTR_PERMISSIONS) == 0)
        {
            LscpAttrs child = {};
            std::string statError;
            if (RemoteStat(JoinRemotePath(path, name), &child, statError) ==
                LSCP_SFTP_STAT_EXISTS)
            {
                entry.isDirectory = (child.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
                    (child.permissions & 0040000) != 0;
                if ((child.flags & LSCP_ATTR_PERMISSIONS) != 0)
                {
                    entry.permissions = child.permissions;
                }
                if ((child.flags & LSCP_ATTR_SIZE) != 0)
                {
                    entry.size = child.size;
                }
                if ((child.flags & LSCP_ATTR_ACMODTIME) != 0)
                {
                    entry.mtime = child.mtime;
                }
            }
        }
        entries.push_back(entry);
    }
    RemoteFreeNames(names);
    return true;
}

bool Script::ParseSyncArguments(const std::vector<std::string> & args,
    const std::string & command, SyncOptions & options,
    std::vector<std::string> & dirs, bool & preview, int & interval,
    int & count, bool & continueOnError, bool modeOptional,
    std::string & error)
{
    error.clear();
    preview = false;
    interval = 10;
    count = 0;
    continueOnError = false;
    bool modeGiven = false;
    bool criteriaGiven = false;
    /* 'option synchdelete on' is the persistent form of '-delete'. */
    options.deleteObsolete = mSyncDeleteDefault;
    options.transferMode = mTransferMode;
    /* Upstream's 'keepuptodate' watches the local directory and reflects
     * its changes onto the remote directory. */
    if (modeOptional)
    {
        options.mode = SyncMode::Remote;
        modeGiven = true;
    }

    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string & a = args[i];
        const std::string lower = ToLower(a);
        if (i == 0 && !modeOptional &&
            (lower == "local" || lower == "remote" || lower == "both"))
        {
            options.mode = lower == "local" ? SyncMode::Local :
                lower == "remote" ? SyncMode::Remote : SyncMode::Both;
            modeGiven = true;
        }
        else if (lower == "-delete")
        {
            options.deleteObsolete = true;
        }
        else if (lower == "-nodelete")
        {
            options.deleteObsolete = false;
        }
        else if (lower == "-mirror")
        {
            options.mirror = true;
        }
        else if (lower == "-continue")
        {
            continueOnError = true;
        }
        else if (StartsWith(lower, "-transfer="))
        {
            TransferMode mode;
            if (!ParseTransferMode(lower.substr(strlen("-transfer=")), mode))
            {
                error = Texts::Translate(
                    "The value of '-transfer' must be binary, ascii or "
                    "automatic.");
                return false;
            }
            options.transferMode = mode;
        }
        else if (lower == "-preview" || lower == "-dryrun")
        {
            preview = true;
        }
        else if (lower == "-nonrecursive" || lower == "-nor")
        {
            options.recursive = false;
        }
        else if (StartsWith(lower, "-conflict="))
        {
            const std::string value = a.substr(strlen("-conflict="));
            if (!ParseSyncConflictPolicy(value, options.conflictPolicy, error))
            {
                return false;
            }
        }
        else if (StartsWith(lower, "-criteria="))
        {
            /* Upstream takes one of 'none', 'either' and 'both', or a
             * comma-separated list of 'time', 'size' and 'checksum'. */
            const std::string value = a.substr(strlen("-criteria="));
            if (!ParseSyncCriteria(value, options.criteria, error))
            {
                return false;
            }
            criteriaGiven = true;
        }
        else if (StartsWith(lower, "-filemask="))
        {
            const std::string value = a.substr(strlen("-filemask="));
            std::string maskError;
            if (!options.mask.Parse(value, maskError))
            {
                error = maskError;
                return false;
            }
        }
        else if (StartsWith(lower, "-interval="))
        {
            /* Strictly digits: atoi() accepted '-interval=12abc' as 12, so
             * a mistyped value became a different interval rather than an
             * error. */
            long long value = 0;
            if (!RawInteger(a.substr(strlen("-interval=")), value) ||
                value < 1 || value > 86400)
            {
                error = Texts::Translate(
                    "The interval must be between 1 and 86400 seconds.");
                return false;
            }
            interval = static_cast<int>(value);
        }
        else if (StartsWith(lower, "-count="))
        {
            long long value = 0;
            if (!RawInteger(a.substr(strlen("-count=")), value) ||
                value < 1 || value > 1000000)
            {
                error = Texts::Translate(
                    "The count must be a positive number of passes.");
                return false;
            }
            count = static_cast<int>(value);
        }
        else if (!a.empty() && a[0] == '-')
        {
            error = Texts::Translate("Unsupported switch '{switch}'; it will not be ignored.",
                {{"switch", a}});
            return false;
        }
        else
        {
            dirs.push_back(a);
        }
    }

    if (!modeGiven || dirs.size() > 2)
    {
        error = Texts::Translate(
            "Syntax: {command}{modes} [-delete] [-nodelete] [-mirror] "
            "[-preview] [-nonrecursive] "
            "[-criteria=time|size|checksum|either|both|none] [-filemask=MASK] "
            "[-transfer=binary|ascii|automatic] [-interval=SECS] [-count=N] "
            "[-continue].",
            {{"command", command},
            {"modes", modeOptional ? std::string(" [LOCAL [REMOTE]]") :
            std::string(" local|remote|both [LOCAL [REMOTE]]")}});
        return false;
    }
    if (options.mirror && options.mode == SyncMode::Both)
    {
        error = Texts::Translate(
            "'-mirror' cannot be combined with the 'both' direction.");
        return false;
    }
    /*
     * In the 'both' direction the record of the previous synchronization
     * decides what changed, and it records timestamps and sizes - upstream
     * drops the criteria for smBoth the same way. A value this branch could
     * not honour is refused rather than quietly ignored.
     */
    if (criteriaGiven && options.mode == SyncMode::Both)
    {
        if (options.criteria.checksum)
        {
            error = Texts::Translate(
                "'-criteria=checksum' cannot be combined with the 'both' "
                "direction, which compares the record of the previous "
                "synchronization instead of the files; synchronize 'local' or "
                "'remote' to compare contents.");
            return false;
        }
        if (options.criteria.Empty())
        {
            error = Texts::Translate(
                "'-criteria=none' cannot be combined with the 'both' "
                "direction: with nothing compared there is no way to tell "
                "which side changed.");
            return false;
        }
    }
    return true;
}

bool Script::BuildSynchronizationPlan(SyncOptions & options,
    const std::string & localDir, const std::string & remoteDir, SyncPlan & plan,
    SyncState * state, std::string & error)
{
    options.state = state;
    LocalSyncFileSystem localFs;
    RemoteSyncFileSystem remoteFs(*this);
    return PlanSynchronization(localFs, remoteFs, localDir, remoteDir,
        options, plan, error);
}

void Script::PrintSynchronizationPlan(const SyncPlan & plan) const
{
    Console & console = Console::Instance();
    console.Write(std::string("SYNCPLAN local=") + plan.localRoot +
        "\tremote=" + plan.remoteRoot +
        "\tmode=" + SyncModeName(plan.mode) +
        "\tcriteria=" + SyncCriteriaName(plan.criteria) +
        "\tmask=" + plan.mask.Describe() + "\n");
    for (size_t i = 0; i < plan.items.size(); i++)
    {
        const SyncItem & item = plan.items[i];
        if (item.action == SyncAction::None)
        {
            continue;
        }
        std::string detail = item.reason;
        if (item.localTime != 0 || item.remoteTime != 0)
        {
            detail += " (local " + DescribeTime(item.localTime) +
                ", remote " + DescribeTime(item.remoteTime) + ")";
        }
        console.Write(std::string(SyncActionName(item.action)) + "\t" + item.path +
            "\t" + detail + "\n");
    }
    char summary[256];
    snprintf(summary, sizeof(summary),
        "SYNCSUMMARY download=%d upload=%d delete-local=%d delete-remote=%d "
        "conflict=%d unchanged=%d bytes=%llu\n",
        plan.Count(SyncAction::Download), plan.Count(SyncAction::Upload),
        plan.Count(SyncAction::DeleteLocal), plan.Count(SyncAction::DeleteRemote),
        plan.Count(SyncAction::Conflict), plan.Count(SyncAction::None),
        plan.Bytes(SyncAction::Download) + plan.Bytes(SyncAction::Upload));
    console.Write(std::string(summary));
}

void Script::RecordSyncState(SyncState * state, const std::string & relative,
    const std::string & localPath, const std::string & remotePath)
{
    if (state == NULL)
    {
        return;
    }
    SyncStateEntry entry;
    const LocalFileInfo info = StatLocal(localPath);
    if (!info.exists)
    {
        return;
    }
    entry.localTime = info.mtime;
    entry.size = info.size;
    LscpAttrs attrs = {};
    std::string error;
    if (RemoteStat(remotePath, &attrs, error) == LSCP_SFTP_STAT_EXISTS)
    {
        if ((attrs.flags & LSCP_ATTR_ACMODTIME) != 0)
        {
            entry.remoteTime = attrs.mtime;
        }
        if ((attrs.flags & LSCP_ATTR_SIZE) != 0)
        {
            entry.size = attrs.size;
        }
    }
    state->Update(relative, entry);
}

bool Script::ExecuteSynchronizationPlan(SyncPlan & plan, const SyncOptions & options,
    bool allowDelete, unsigned long long & bytesTransferred)
{
    Console & console = Console::Instance();
    bool success = true;
    bool deleteAllowed = allowDelete && options.deleteObsolete;

    if (deleteAllowed && plan.HasConflicts())
    {
        console.Error(Texts::Translate(
            "The plan has {count} conflict(s); nothing was deleted. Resolve the "
            "conflicts (or synchronize without -delete) and run the "
            "synchronization again.",
            {{"count", std::to_string(plan.Count(SyncAction::Conflict))}}));
        deleteAllowed = false;
        mErrors++;
        success = false;
    }

    for (size_t i = 0; i < plan.items.size(); i++)
    {
        const SyncItem & item = plan.items[i];
        const std::string localPath =
            LocalPathForRelative(plan.localRoot, item.path);
        const std::string remotePath =
            RemotePathForRelative(plan.remoteRoot, item.path);
        std::string error;

        switch (item.action)
        {
            case SyncAction::None:
                RecordSyncState(options.state, item.path, localPath, remotePath);
                break;

            case SyncAction::Conflict:
                console.Error(Texts::Translate(
                    "Conflict: '{path}' {reason}, so it was left unchanged.",
                    {{"path", item.path}, {"reason", item.reason}}));
                mErrors++;
                success = false;
                break;

            case SyncAction::Upload:
                if (item.isDirectory)
                {
                    if (!CreateRemoteDirectoryRecursive(remotePath, error))
                    {
                        console.Error(Texts::RemoteError("create directory",
                            remotePath, error));
                        mErrors++;
                        success = false;
                    }
                    else
                    {
                        console.Status(Texts::Translate("Created remote directory '{path}'.",
                            {{"path", remotePath}}));
                    }
                    break;
                }
                if (!CreateRemoteDirectoryRecursive(RemoteDirName(remotePath), error))
                {
                    console.Error(Texts::RemoteError("create directory",
                        RemoteDirName(remotePath), error));
                    mErrors++;
                    success = false;
                    break;
                }
                {
                    console.TransferStart(item.path, item.localSize);
                    unsigned long long size = 0;
                    const int result = RemotePutMode(localPath, remotePath,
                        options.transferMode, item.localSize, &size, error);
                    console.TransferEnd(result == 0);
                    if (result != 0)
                    {
                        console.Error(Texts::TransferFailed(remotePath, error));
                        mErrors++;
                        success = false;
                        break;
                    }
                    bytesTransferred += size;
                    console.Status(Texts::Translate("Uploaded ") +
                        Texts::FileTransferred(remotePath, size));
                    RecordSyncState(options.state, item.path, localPath, remotePath);
                }
                break;

            case SyncAction::Download:
                if (item.isDirectory)
                {
                    if (!CreateLocalDirectoryRecursive(localPath, error))
                    {
                        console.Error(Texts::LocalError("create directory",
                            localPath, error));
                        mErrors++;
                        success = false;
                    }
                    else
                    {
                        console.Status(Texts::Translate("Created local directory '{path}'.",
                            {{"path", localPath}}));
                    }
                    break;
                }
                if (!CreateLocalDirectoryRecursive(LocalDirName(localPath), error))
                {
                    console.Error(Texts::LocalError("create directory",
                        LocalDirName(localPath), error));
                    mErrors++;
                    success = false;
                    break;
                }
                {
                    console.TransferStart(item.path, item.remoteSize);
                    unsigned long long size = 0;
                    const int result = RemoteGetMode(remotePath, localPath,
                        options.transferMode, item.remoteSize, &size, error);
                    console.TransferEnd(result == 0);
                    if (result != 0)
                    {
                        console.Error(Texts::TransferFailed(remotePath, error));
                        mErrors++;
                        success = false;
                        break;
                    }
                    bytesTransferred += size;
                    console.Status(Texts::Translate("Downloaded ") +
                        Texts::FileTransferred(localPath, size));
                    RecordSyncState(options.state, item.path, localPath, remotePath);
                }
                break;

            case SyncAction::DeleteLocal:
                if (!deleteAllowed)
                {
                    if (options.deleteObsolete)
                    {
                        console.Status(Texts::Translate("Kept '{path}'.",
                            {{"path", localPath}}));
                    }
                    break;
                }
                if (!ConfirmObsolete("local", localPath, item.isDirectory))
                {
                    success = false;
                    break;
                }
                if (!RemoveLocalItemRecursive(localPath))
                {
                    success = false;
                    break;
                }
                if (options.state != NULL)
                {
                    options.state->Remove(item.path);
                }
                break;

            case SyncAction::DeleteRemote:
                if (!deleteAllowed)
                {
                    if (options.deleteObsolete)
                    {
                        console.Status(Texts::Translate("Kept '{path}'.",
                            {{"path", remotePath}}));
                    }
                    break;
                }
                if (!ConfirmObsolete("remote", remotePath, item.isDirectory))
                {
                    success = false;
                    break;
                }
                if (!RemoveRemoteItemRecursive(remotePath))
                {
                    success = false;
                    break;
                }
                if (options.state != NULL)
                {
                    options.state->Remove(item.path);
                }
                break;
        }
    }
    return success;
}

bool Script::SynchronizeDirectories(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    SyncOptions options;
    std::vector<std::string> dirs;
    bool preview = false;
    int interval = 10;
    int count = 0;
    bool continueOnError = false;
    std::string parseError;
    if (!ParseSyncArguments(args, "synchronize", options, dirs, preview,
        interval, count, continueOnError, false, parseError))
    {
        console.Error(Texts::WrongArguments("synchronize", parseError));
        mErrors++;
        return false;
    }
    if (!RequireConnection())
    {
        return false;
    }

    std::string error;
    std::string localDir = dirs.size() > 0 ? ExpandTilde(dirs[0]) : GetLocalDirectory(error);
    std::string remoteDir = dirs.size() > 1 ?
        ResolveRemotePath(mRemoteDirectory, dirs[1]) : mRemoteDirectory;
    if (localDir.empty())
    {
        console.Error(Texts::Translate("Cannot determine local directory: {reason}",
            {{"reason", error}}));
        mErrors++;
        return false;
    }
    if (remoteDir.empty())
    {
        remoteDir = "/";
    }

    /* The memory of the previous pass: what makes 'both' able to tell a
     * conflict from a change, and a deletion from a new file. */
    SyncState state;
    const std::string stateKey = SyncState::MakeKey(
        mSession.IsOpen() ? mSession.Options().hostName : std::string(),
        localDir, remoteDir);
    const std::string statePath = SyncState::DefaultPath(stateKey);
    std::string stateError;
    if (!state.Load(statePath, stateError))
    {
        console.Error(stateError);
        mErrors++;
        return false;
    }
    const bool firstPass = state.Empty();

    SyncPlan plan;
    if (!BuildSynchronizationPlan(options, localDir, remoteDir, plan, &state, error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }

    if (preview)
    {
        PrintSynchronizationPlan(plan);
        return true;
    }

    if (options.deleteObsolete &&
        (IsFileSystemRoot(localDir) || IsFileSystemRoot(remoteDir)))
    {
        console.Error(Texts::Translate(
            "Refusing to delete obsolete entries directly in the root directory "
            "'{path}'. Synchronize a subdirectory instead.",
            {{"path", IsFileSystemRoot(localDir) ? localDir : remoteDir}}));
        mErrors++;
        return false;
    }
    if (options.mode == SyncMode::Both && options.deleteObsolete && firstPass)
    {
        /* Without a previous pass there is no way to tell a file that was
         * deleted on one side from a file that was created on the other,
         * so this pass only transfers and records what it saw. */
        console.Status(Texts::Translate(
            "No previous synchronization of these directories is on record: "
            "this pass transfers files but deletes nothing. Run it again to "
            "let deletions follow."));
    }

    console.Status(Texts::Translate(
        "Synchronizing ({mode}) '{local}' and '{remote}'...",
        {{"mode", std::string(SyncModeName(options.mode))},
        {"local", localDir}, {"remote", remoteDir}}));

    unsigned long long bytes = 0;
    bool ok = ExecuteSynchronizationPlan(plan, options, true, bytes);

    if (!statePath.empty())
    {
        std::string saveError;
        if (!state.Save(statePath, saveError))
        {
            console.Error(saveError);
            mErrors++;
            ok = false;
        }
    }
    console.Status(ok ? "Synchronization completed." : "Synchronization failed.");
    return ok;
}

bool Script::KeepUpToDate(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    SyncOptions options;
    std::vector<std::string> dirs;
    bool preview = false;
    int interval = 10;
    int count = 0;
    bool continueOnError = false;
    std::string parseError;
    if (!ParseSyncArguments(args, "keepuptodate", options, dirs, preview,
        interval, count, continueOnError, true, parseError))
    {
        console.Error(Texts::WrongArguments("keepuptodate", parseError));
        mErrors++;
        return false;
    }
    if (!RequireConnection())
    {
        return false;
    }
    if (count == 0 && !console.IsInteractive())
    {
        console.Error(Texts::WrongArguments("keepuptodate",
            Texts::Translate(
                "It would run until it is interrupted; give -count=<passes> to "
                "run a fixed number of passes.")));
        mErrors++;
        return false;
    }

    std::string error;
    std::string localDir = dirs.size() > 0 ? ExpandTilde(dirs[0]) : GetLocalDirectory(error);
    std::string remoteDir = dirs.size() > 1 ?
        ResolveRemotePath(mRemoteDirectory, dirs[1]) : mRemoteDirectory;
    if (localDir.empty())
    {
        console.Error(Texts::Translate("Cannot determine local directory: {reason}",
            {{"reason", error}}));
        mErrors++;
        return false;
    }
    if (remoteDir.empty())
    {
        remoteDir = "/";
    }
    if (options.deleteObsolete &&
        (IsFileSystemRoot(localDir) || IsFileSystemRoot(remoteDir)))
    {
        console.Error(Texts::Translate(
            "Refusing to delete obsolete entries directly in the root directory; "
            "synchronize a subdirectory instead."));
        mErrors++;
        return false;
    }

    SyncState state;
    const std::string statePath = SyncState::DefaultPath(SyncState::MakeKey(
        mSession.IsOpen() ? mSession.Options().hostName : std::string(),
        localDir, remoteDir));
    std::string stateError;
    if (!state.Load(statePath, stateError))
    {
        console.Error(stateError);
        mErrors++;
        return false;
    }

    LocalChangeWatcher watcher;
    bool eventDriven = watcher.Start(localDir);
    InstallInterruptHandler();
    if (eventDriven)
    {
        console.Status(Texts::Translate(
            "Watching local changes in '{local}' and keeping remote "
            "'{remote}' up to date (full check every {interval} seconds). "
            "Press Ctrl-C to stop.",
            {{"local", localDir}, {"remote", remoteDir},
            {"interval", std::to_string(interval)}}));
    }
    else
    {
        console.Status(Texts::Translate(
            "Watching '{local}' and '{remote}' every {interval} seconds. "
            "Press Ctrl-C to stop.",
            {{"local", localDir}, {"remote", remoteDir},
            {"interval", std::to_string(interval)}}));
    }

    bool ok = true;
    for (int pass = 1; count == 0 || pass <= count; pass++)
    {
        if (Interrupted())
        {
            console.Status(Texts::Translate("Stopped watching."));
            break;
        }
        if (!mSession.IsOpen() || !mSession.IsAlive())
        {
            console.Error(Texts::NotConnected());
            mErrors++;
            ok = false;
            break;
        }

        bool passOk = true;
        SyncPlan plan;
        if (!BuildSynchronizationPlan(options, localDir, remoteDir, plan, &state, error))
        {
            console.Error(error);
            mErrors++;
            ok = false;
            passOk = false;
        }
        else if (preview)
        {
            PrintSynchronizationPlan(plan);
        }
        else if (plan.Count(SyncAction::Upload) == 0 &&
            plan.Count(SyncAction::Download) == 0 &&
            plan.Count(SyncAction::DeleteLocal) == 0 &&
            plan.Count(SyncAction::DeleteRemote) == 0 &&
            plan.Count(SyncAction::Conflict) == 0)
        {
            console.Status(Texts::Translate(
                "Pass {pass}: nothing to do (every file is up to date).",
                {{"pass", std::to_string(pass)}}));
        }
        else
        {
            unsigned long long bytes = 0;
            if (!ExecuteSynchronizationPlan(plan, options, true, bytes))
            {
                ok = false;
                passOk = false;
            }
            if (!statePath.empty())
            {
                std::string saveError;
                if (!state.Save(statePath, saveError))
                {
                    console.Error(saveError);
                    mErrors++;
                    ok = false;
                    passOk = false;
                }
            }
        }
        if (!passOk && !continueOnError)
        {
            break;
        }

        if (count != 0 && pass == count)
        {
            break;
        }
        if (Interrupted())
        {
            console.Status(Texts::Translate("Stopped watching."));
            break;
        }
        if (eventDriven)
        {
            /* Local changes trigger an immediate comparison; the timeout is
             * still a safety rescan if a filesystem event was lost. */
            watcher.WaitForChange(static_cast<unsigned>(interval * 1000));
            if (!watcher.Available())
            {
                eventDriven = false;
                console.Status(Texts::Translate(
                    "Native local change notifications stopped; continuing with "
                    "timer polling."));
            }
        }
        else
        {
            /* Sleep in small steps so that Ctrl-C ends the fallback wait. */
            for (int waited = 0; waited < interval * 4; waited++)
            {
                if (Interrupted())
                {
                    break;
                }
                SleepMilliseconds(250);
            }
        }
    }
    return ok;
}

/* ------------------------------------------------------------------ *
 * Remote editing                                                      *
 * ------------------------------------------------------------------ */

namespace {

/* The open connection seen through the interface Editor needs. */
class ScriptFileAccess : public RemoteFileAccess
{
public:
    explicit ScriptFileAccess(Script & script) : mScript(script) {}

    virtual int Stat(const std::string & path, LscpAttrs & attrs, std::string & error)
    {
        return mScript.StatForEdit(path, attrs, error);
    }

    virtual int Download(const std::string & remote, const std::string & local,
        bool preserveTime, std::string & error)
    {
        return mScript.DownloadForEdit(remote, local, preserveTime, error);
    }

    virtual int Upload(const std::string & local, const std::string & remote,
        bool preserveTime, std::string & error)
    {
        return mScript.UploadForEdit(local, remote, preserveTime, error);
    }

private:
    Script & mScript;
};

} // namespace

bool Script::EditRemoteFile(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();

    EditOptions options;
    options.editor = mEditor;
    options.maxSize = mEditMaxSize;
    std::vector<std::string> paths;
    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string & a = args[i];
        const std::string lower = ToLower(a);
        if (lower == "-force")
        {
            options.force = true;
        }
        else if (lower == "-keep" || lower == "-keeptemp")
        {
            options.keepTempFile = true;
        }
        else if (lower == "-binary")
        {
            options.allowBinary = true;
        }
        else if (StartsWith(lower, "-editor="))
        {
            options.editor = a.substr(strlen("-editor="));
        }
        else if (StartsWith(lower, "-eol="))
        {
            const std::string eol = lower.substr(strlen("-eol="));
            if (eol != "preserve" && eol != "lf" && eol != "crlf")
            {
                console.Error(Texts::WrongArguments("edit",
                    Texts::Translate("The value of '-eol' must be preserve, lf or crlf.")));
                mErrors++;
                return false;
            }
            options.eol = eol;
        }
        else if (lower == "-monitor")
        {
            options.monitor = true;
            options.monitorPasses = 1;
        }
        else if (StartsWith(lower, "-monitor="))
        {
            const std::string val = a.substr(strlen("-monitor="));
            /* Strictly digits: atoi() accepted '-monitor=3abc' as 3, so a
             * mistyped value became a different number of passes rather
             * than an error. */
            long long passes = 0;
            if (!RawInteger(val, passes) || passes <= 0 ||
                passes > static_cast<long long>(UINT_MAX))
            {
                console.Error(Texts::WrongArguments("edit",
                    Texts::Translate(
                        "The value of '-monitor' must be a positive number of passes.")));
                mErrors++;
                return false;
            }
            options.monitor = true;
            options.monitorPasses = static_cast<unsigned>(passes);
        }
        else if (!a.empty() && a[0] == '-')
        {
            console.Error(Texts::WrongArguments("edit",
                Texts::Translate("Unsupported switch '{switch}'; it will not be ignored.",
                    {{"switch", a}})));
            mErrors++;
            return false;
        }
        else
        {
            paths.push_back(a);
        }
    }

    if (paths.size() != 1)
    {
        console.Error(Texts::WrongArguments("edit",
            Texts::Translate(
                "Syntax: edit [-force] [-keep] [-editor=COMMAND] <remotefile>. "
                "One file at a time.")));
        mErrors++;
        return false;
    }
    /* The switches are read before the connection is asked for, the way
     * 'synchronize' and 'keepuptodate' read theirs: a command that cannot
     * run as written should say so without opening a session first. */
    if (!RequireConnection())
    {
        return false;
    }

    ScriptFileAccess access(*this);
    RemoteEditor editor(access, &console);
    std::string error;
    if (editor.Edit(ResolveRemotePath(mRemoteDirectory, paths[0]), options,
        mConfirm, error))
    {
        return true;
    }
    console.Error(error);
    mErrors++;
    return false;
}

/* ------------------------------------------------------------------ *
 * Transfer presets (the copy parameter lists)                         *
 * ------------------------------------------------------------------ */

bool Script::SavePresetCommand(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    if (args.size() < 2)
    {
        console.Error(Texts::WrongArguments("savepreset",
            Texts::Translate(
                "Syntax: savepreset <name> <setting>[=<value>]... "
                "(settings: transfer=, preservetime=, neweronly, speed=, "
                "resumesupport=, permissions=, host=, user=, remotedir=, "
                "localdir=, mask=).")));
        mErrors++;
        return false;
    }
    const std::string & name = args[0];
    if (!TransferPresetStore::IsValidName(name))
    {
        console.Error(Texts::WrongArguments("savepreset",
            Texts::Translate("The preset name '{name}' is not valid.",
                {{"name", name}})));
        mErrors++;
        return false;
    }
    std::string error;
    if (!mPresets.Load(error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    /* Saving over an existing preset updates only the settings the
     * command names, like re-ticking a few boxes of the same
     * copy-parameter list. */
    TransferPreset preset;
    const TransferPreset * previous = mPresets.Find(name);
    if (previous != NULL)
    {
        preset = *previous;
    }
    else
    {
        preset.name = name;
    }
    for (size_t i = 1; i < args.size(); i++)
    {
        std::string setting = args[i];
        if (!setting.empty() && setting[0] == '-')
        {
            setting.erase(0, 1);
        }
        const size_t eq = setting.find('=');
        const std::string key = eq != std::string::npos ?
            setting.substr(0, eq) : setting;
        const std::string value = eq != std::string::npos ?
            setting.substr(eq + 1) : std::string();
        if (!mPresets.ParseSetting(key, value, preset, error))
        {
            console.Error(Texts::WrongArguments("savepreset", error));
            mErrors++;
            return false;
        }
    }
    if (!mPresets.AddOrUpdate(preset, error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    if (!mPresets.Save(error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    console.Status(Texts::Translate("Stored transfer preset '{name}'.",
        {{"name", preset.name}}));
    return true;
}

bool Script::RemovePresetCommand(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    if (args.size() != 1)
    {
        console.Error(Texts::WrongArguments("rmspreset",
            Texts::Translate("Syntax: rmspreset <name>.")));
        mErrors++;
        return false;
    }
    std::string error;
    if (!mPresets.Load(error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    const TransferPreset * existing = mPresets.Find(args[0]);
    if (existing == NULL)
    {
        console.Error(Texts::WrongArguments("rmspreset",
            Texts::Translate(
                "There is no transfer preset named '{name}' in '{path}'.",
                {{"name", args[0]}, {"path", mPresets.Path()}})));
        mErrors++;
        return false;
    }
    const std::string name = existing->name;
    if (!mPresets.Remove(name, error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    if (!mPresets.Save(error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    if (mActivePresetName == name)
    {
        mActivePresetName.clear();
    }
    console.Status(Texts::Translate("Removed transfer preset '{name}'.",
        {{"name", name}}));
    return true;
}

bool Script::ListPresetsCommand(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    if (!args.empty())
    {
        console.Error(Texts::WrongArguments("presets",
            Texts::Translate("Syntax: presets.")));
        mErrors++;
        return false;
    }
    std::string error;
    if (!mPresets.Load(error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    if (mPresets.Presets().empty())
    {
        console.Status(Texts::Translate(
            "There are no transfer presets in '{path}' (create one with "
            "'savepreset').", {{"path", mPresets.Path()}}));
        return true;
    }
    console.Status(Texts::Translate("Transfer presets in '{path}':",
        {{"path", mPresets.Path()}}));
    for (size_t i = 0; i < mPresets.Presets().size(); i++)
    {
        const TransferPreset & preset = mPresets.Presets()[i];
        console.Status(Texts::Translate(" {name}{active} - {description}",
            {{"name", preset.name},
            {"active", preset.name == mActivePresetName ? " (active)" : ""},
            {"description", preset.Describe()}}));;
    }
    return true;
}

/* ------------------------------------------------------------------ *
 * Stored sessions (the site manager)                                  *
 * ------------------------------------------------------------------ */

/*
 * Upstream 'session' lists the open sessions as 'index<2 spaces>name' and
 * prints which one is active; with an argument (a 1-based index) it
 * switches to that session and prints only the active line. A CheckSession
 * comes first, so an offline 'session' is an error like upstream's. Only
 * one connection exists here, so index 1 is the only one that resolves.
 */
bool Script::SessionCommand(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() > 1)
    {
        Console::Instance().Error(Texts::WrongArguments("session",
            Texts::Translate("Syntax: session [<index>].")));
        mErrors++;
        return false;
    }
    if (!args.empty() && args[0] != "1")
    {
        Console::Instance().Error(Texts::Translate(
            "Invalid session index '{index}'.", {{"index", args[0]}}));
        mErrors++;
        return false;
    }
    const std::string name = mSessionDisplayName.empty() ?
        (mSession.Options().hostName.empty() ? std::string("session") :
            mSession.Options().hostName) : mSessionDisplayName;
    if (args.empty())
    {
        char index[8];
        snprintf(index, sizeof(index), "%3d", 1);
        Console::Instance().WriteLine(std::string(index) + "  " + name);
    }
    Console::Instance().WriteLine(Texts::Translate(
        "Active session: {index} ({name})",
        {{"index", std::string("1")}, {"name", name}}));
    return true;
}

/*
 * 'sessions' is the stored-sites side of the console: listing them, the
 * export/import helpers and looking one up by name. Upstream spells none
 * of this 'session' - its 'session' switches between open connections,
 * which is SessionCommand below - so the name follows this client's
 * plural convention instead.
 */
bool Script::StoredSessionsCommand(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    const std::string path = mSessions.Path();

    if (args.size() >= 2 && ToLower(args[0]) == "export")
    {
        std::string error;
        if (args.size() != 2)
        {
            console.Error(Texts::WrongArguments("sessions",
                Texts::Translate("Syntax: session export <file>.")));
            mErrors++;
            return false;
        }
        if (!mSessions.ExportFile(ExpandTilde(args[1]), error))
        {
            console.Error(error);
            mErrors++;
            return false;
        }
        console.Status(Texts::Translate(
            "Exported {count} session(s) to '{path}'.",
            {{"count", std::to_string(mSessions.Sessions().size())},
            {"path", args[1]}}));
        return true;
    }

    if (args.size() >= 2 && ToLower(args[0]) == "import")
    {
        if (args.size() != 2)
        {
            console.Error(Texts::WrongArguments("sessions",
                Texts::Translate("Syntax: session import <file>.")));
            mErrors++;
            return false;
        }
        const bool merge = true;
        std::string error;
        const int imported = mSessions.ImportFile(ExpandTilde(args[1]), merge, error);
        if (imported == 0)
        {
            console.Error(Texts::Translate(
                "No sessions were imported from '{path}'; {reason}",
                {{"path", args[1]},
                {"reason", error.empty() ? std::string("the file has none.") :
                error}}));
            mErrors++;
            return false;
        }
        if (!mSessions.Save(error))
        {
            console.Error(error);
            mErrors++;
            return false;
        }
        console.Status(Texts::Translate(
            "Imported {count} session(s) from '{path}'.",
            {{"count", std::to_string(imported)}, {"path", args[1]}}));
        return true;
    }

    if (args.size() == 1 && ToLower(args[0]) == "list")
    {
        return StoredSessionsCommand(std::vector<std::string>());
    }

    if (args.size() == 1 && ToLower(args[0]) == "folders")
    {
        const std::vector<std::string> folders = mSessions.Folders();
        if (folders.empty())
        {
            console.WriteLine(Texts::Translate("There are no session folders."));
            return true;
        }
        for (size_t i = 0; i < folders.size(); i++)
        {
            console.WriteLine("  " + folders[i] + "/");
        }
        return true;
    }

    if (args.size() == 1 &&
        (StartsWith(ToLower(args[0]), "-folder=") ||
         (args[0].size() > 1 && args[0][args[0].size() - 1] == '/')))
    {
        const std::string folder = StartsWith(ToLower(args[0]), "-folder=") ?
            args[0].substr(strlen("-folder=")) : args[0];
        const std::vector<StoredSession> inFolder =
            mSessions.SessionsInFolder(folder);
        if (inFolder.empty())
        {
            console.Error(Texts::Translate(
                "There are no stored sessions in folder '{folder}'.",
                {{"folder", folder}}));
            mErrors++;
            return false;
        }
        for (size_t i = 0; i < inFolder.size(); i++)
        {
            console.WriteLine("  " + inFolder[i].name);
        }
        return true;
    }

    if (args.size() == 1)
    {
        const StoredSession * stored = mSessions.Find(args[0]);
        if (stored == NULL)
        {
            console.Error(Texts::Translate(
                "There is no stored session named '{name}'.",
                {{"name", args[0]}}));
            mErrors++;
            return false;
        }
        return OpenStoredSite(stored->name);
    }

    if (args.size() > 1)
    {
        console.Error(Texts::WrongArguments("session",
            Texts::Translate("Syntax: sessions [NAME|list|export <file>|import <file>].")));
        mErrors++;
        return false;
    }

    if (mSessions.Empty())
    {
        console.WriteLine(Texts::Translate(
            "There are no stored sessions. Use 'savesession <name>' to store "
            "the current connection."));
        if (!path.empty())
        {
            console.WriteLine(Texts::Translate("Sessions are stored in {path}",
                {{"path", path}}));
        }
        return true;
    }

    console.WriteLine(Texts::Translate("Stored sessions in {path}:",
        {{"path", path.empty() ? std::string("(no configuration directory)")
        : path}}));
    const std::vector<StoredSession> & sessions = mSessions.Sessions();
    size_t width = 0;
    for (size_t i = 0; i < sessions.size(); i++)
    {
        width = sessions[i].name.size() > width ? sessions[i].name.size() : width;
    }
    for (size_t i = 0; i < sessions.size(); i++)
    {
        std::string url = sessions[i].protocol.empty() ?
            std::string("sftp") : sessions[i].protocol;
        url += "://";
        if (!sessions[i].userName.empty())
        {
            url += sessions[i].userName + "@";
        }
        url += sessions[i].hostName.empty() ? std::string("?") : sessions[i].hostName;
        if (sessions[i].portNumber > 0 && sessions[i].portNumber != 22)
        {
            url += ":" + std::to_string(sessions[i].portNumber);
        }
        std::string line = "  " + sessions[i].name;
        line.append(width - sessions[i].name.size() + 2, ' ');
        line += url;
        if (!sessions[i].remoteDirectory.empty())
        {
            line += "  -> " + sessions[i].remoteDirectory;
        }
        if (!sessions[i].preset.empty())
        {
            line += "  (preset " + sessions[i].preset + ")";
        }
        console.WriteLine(line);
    }
    return true;
}

bool Script::OpenStoredSite(const std::string & name,
    const OpenSwitches & switches)
{
    const StoredSession * stored = mSessions.Find(name);
    if (stored == NULL)
    {
        return false;
    }
    /*
     * The site brings its transfer preset along: a stored site defines
     * its own defaults, so an empty value clears whatever preset an
     * earlier connection had left active.
     */
    mActivePresetName = stored->preset;
    mPresetOff = false;
    std::string error;
    if (mSession.IsOpen())
    {
        CloseSite(std::vector<std::string>());
    }

    if (!stored->proxyError.empty())
    {
        Console::Instance().Error(Texts::Translate(
            "The proxy of the stored session '{name}' cannot be used: {reason}. "
            "The site is not opened without the proxy it was stored with; "
            "store the proxy again with 'savesession {name} "
            "-rawsettings ProxyMethod=... ProxyHost=...'.",
            {{"name", stored->name}, {"reason", stored->proxyError}}));
        mErrors++;
        return false;
    }

    const std::string storedError = !stored->settingError.empty() ? stored->settingError :
        (stored->tunnel.enabled ? stored->tunnelError : std::string());
    if (!storedError.empty())
    {
        Console::Instance().Error(Texts::Translate(
            "The settings of stored session '{name}' cannot be used: {reason}.",
            {{"name", stored->name}, {"reason", storedError}}));
        mErrors++;
        return false;
    }

    SessionOptions options = SessionStore::ToSessionOptions(*stored, mDefaults);
    /* The switches of the command change the settings of the site: a
     * password typed for this connection, a host key accepted for it, or a
     * proxy given as raw settings. */
    if (!ApplyOpenSwitches(switches, options, error))
    {
        Console::Instance().Error(Texts::WrongArguments("open", error));
        mErrors++;
        return false;
    }
    if (options.userName.empty())
    {
        options.userName = CurrentUserName();
    }
    Console & console = Console::Instance();
    if (stored->passwordStored && stored->password.empty() &&
        !stored->passwordError.empty())
    {
        /*
         * Not fatal: a key file or an agent may be enough, and a
         * password-only session will fail at authentication with this
         * already on screen to explain why.
         */
        console.Error(Texts::Translate(
            "The stored password of session '{name}' cannot be used: {reason}. "
            "Continuing without it.",
            {{"name", stored->name}, {"reason", stored->passwordError}}));
    }
    console.Status(Texts::Translate("Connecting to {host} (stored session '{name}')...", {{"host", options.hostName}, {"name", stored->name}}));
    if (!mSession.Open(options, error))
    {
        console.Error(Texts::CannotOpenSession(options.hostName, error));
        mErrors++;
        return false;
    }

    mHomeDirectory.clear();
    if (UseNativeSftp(mSession.Options().protocol))
    {
        if (lscp_sftp_init() != 0)
        {
            console.Error(lscp_sftp_error());
            mSession.Close();
            mErrors++;
            return false;
        }
        char * home = lscp_sftp_realpath(".");
        if (home != NULL)
        {
            mHomeDirectory = home;
            free(home);
        }
        std::string initial = options.initialDirectory.empty() ?
            std::string(".") : options.initialDirectory;
        char * canonical = lscp_sftp_realpath(initial.c_str());
        if (canonical == NULL)
        {
            console.Error(lscp_sftp_error());
            mSession.Close();
            mErrors++;
            return false;
        }
        mRemoteDirectory = canonical;
        free(canonical);
    }
    else if (UseNativeScp(mSession.Options().protocol))
    {
        std::string home;
        std::string resolved;
        if (!ScpClient::ResolveHomeAndInitial(mSession.Options(),
                options.initialDirectory, home, resolved, error))
        {
            console.Error(Texts::CannotOpenSession(options.hostName, error));
            mSession.Close();
            mErrors++;
            return false;
        }
        mHomeDirectory = home;
        mRemoteDirectory = resolved;
    }
    else
    {
        mRemoteDirectory = options.initialDirectory.empty() ?
            std::string("/") : options.initialDirectory;
        mHomeDirectory = mRemoteDirectory;
    }

    if (!stored->localDirectory.empty())
    {
        std::string localError;
        if (!SetLocalDirectory(ExpandTilde(stored->localDirectory), localError))
        {
            console.Error(Texts::LocalError("change the directory",
                stored->localDirectory, localError));
        }
    }

    mStoredSessionName = stored->name;
    mSessionDisplayName = switches.sessionNameGiven ? switches.sessionName :
        stored->name;
    /* A stored site names the XML log's '<session>' root, as upstream's
     * stored sessions name theirs. */
    console.XmlSessionName(switches.sessionNameGiven ? switches.sessionName :
        stored->name);
    console.Status(Texts::Translate("Connected, the remote directory is {path}", {{"path", mRemoteDirectory}}));

    /* Remember when this session was last used; a failure to record it
     * does not break the connection. */
    StoredSession updated = *stored;
    updated.lastUsed = static_cast<unsigned long long>(std::time(NULL));
    std::string saveError;
    if (mSessions.AddOrUpdate(updated, saveError))
    {
        mSessions.Save(saveError);
    }
    return true;
}

bool Script::SaveStoredSession(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    if (args.empty())
    {
        console.Error(Texts::WrongArguments("savesession",
            Texts::Translate(
                "Syntax: savesession <name> [-host=HOST] [-port=N] "
                "[-username=NAME] [-protocol=SCHEME] [-privatekey=FILE] "
                "[-hostkey=KEY] [-remotedir=DIR] [-localdir=DIR] "
                "[-preset=NAME] [-rawsettings NAME=VALUE...] [-password] "
                "[-password=PWD].")));
        mErrors++;
        return false;
    }

    const std::string name = args[0];
    if (!SessionStore::IsValidName(name))
    {
        console.Error(Texts::WrongArguments("savesession",
            Texts::Translate("The session name '{name}' is not valid.",
                {{"name", name}})));
        mErrors++;
        return false;
    }

    SessionOptions options = mDefaults;
    bool connected = mSession.IsOpen();
    if (connected)
    {
        options = mSession.Options();
    }
    else
    {
        options.hostName.clear();
        options.initialDirectory.clear();
    }

    std::string localDirectory;
    std::string remoteDirectory = mRemoteDirectory;
    std::string storedPreset;
    bool presetGiven = false;
    bool savePassword = false;
    std::string explicitPassword;
    bool passwordGiven = false;
    bool portGiven = false;
    bool protocolGiven = false;
    /* Upstream's session settings, applied on top of the proxy the site
     * already has: 'savesession <name> -rawsettings ProxyMethod=SOCKS5
     * ProxyHost=proxy.example.com'. */
    std::vector<RawSetting> rawSettings;

    for (size_t i = 1; i < args.size(); i++)
    {
        const std::string & a = args[i];
        const std::string lower = ToLower(a);
        if (StartsWith(lower, "-host="))
        {
            options.hostName = a.substr(strlen("-host="));
        }
        else if (StartsWith(lower, "-port="))
        {
            /* atoi() was used here before: it stops at the first character
             * that is not a digit and returns 0 for text, so '-port=22x'
             * stored port 22 and '-port=ssh' stored no port at all, with
             * nothing to say either had happened. A stored site is opened
             * later by a script that cannot ask, so the value has to be
             * whole and in range now. */
            const std::string value = a.substr(strlen("-port="));
            long long port = 0;
            if (!RawInteger(value, port) || port < 1 || port > 65535)
            {
                console.Error(Texts::WrongArguments("savesession",
                    Texts::Translate(
                        "Invalid port number '{value}' (expected 1 through 65535).",
                        {{"value", value}})));
                mErrors++;
                return false;
            }
            options.portNumber = static_cast<int>(port);
            portGiven = true;
        }
        else if (StartsWith(lower, "-username="))
        {
            options.userName = a.substr(strlen("-username="));
        }
        else if (StartsWith(lower, "-protocol="))
        {
            protocolGiven = true;
            /* Checked against the schemes 'open' accepts: a stored site is
             * opened later by a script that cannot ask, so a protocol
             * nothing here connects with is refused now rather than stored
             * and failed at open time. */
            const std::string scheme = ToLower(a.substr(strlen("-protocol=")));
            std::string protocol;
            if (!ResolveProtocolScheme(scheme, protocol))
            {
                console.Error(Texts::WrongArguments("savesession",
                    Texts::Translate("Unsupported protocol '{protocol}'.",
                        {{"protocol", scheme}})));
                mErrors++;
                return false;
            }
            options.protocol = protocol;
        }
        else if (StartsWith(lower, "-privatekey="))
        {
            options.privateKeyFile = ExpandTilde(a.substr(strlen("-privatekey=")));
        }
        else if (StartsWith(lower, "-hostkey="))
        {
            options.hostKey = a.substr(strlen("-hostkey="));
        }
        else if (StartsWith(lower, "-remotedir="))
        {
            remoteDirectory = a.substr(strlen("-remotedir="));
        }
        else if (StartsWith(lower, "-localdir="))
        {
            localDirectory = ExpandTilde(a.substr(strlen("-localdir=")));
        }
        else if (a == "-preset=" || StartsWith(lower, "-preset="))
        {
            /* The help of this command offers '-preset=' as the way to
             * clear the preset a site loads, so the empty value is the
             * switch's own meaning here and not a missing one. */
            storedPreset = a.substr(strlen("-preset="));
            presetGiven = true;
        }
        else if (a == "-rawsettings" || StartsWith(lower, "-rawsettings="))
        {
            std::string rawError;
            if (!CollectRawSettings(args, i, rawSettings, rawError))
            {
                console.Error(Texts::WrongArguments("savesession", rawError));
                mErrors++;
                return false;
            }
        }
        else if (lower == "-password")
        {
            savePassword = true;
        }
        else if (StartsWith(lower, "-password="))
        {
            explicitPassword = a.substr(strlen("-password="));
            passwordGiven = true;
            savePassword = true;
        }
        else
        {
            console.Error(Texts::WrongArguments("savesession",
                Texts::Translate("Unknown switch '{switch}'.", {{"switch", a}})));
            mErrors++;
            return false;
        }
    }

    if (localDirectory.empty() && connected)
    {
        std::string error;
        localDirectory = GetLocalDirectory(error);
    }

    if (options.hostName.empty())
    {
        console.Error(Texts::WrongArguments("savesession",
            Texts::Translate(
                "There is no host to store: connect first, or give -host=HOST.")));
        mErrors++;
        return false;
    }

    StoredSession session = SessionStore::FromSessionOptions(name, options,
        remoteDirectory, localDirectory);
    /* The transfer preset of this site: -preset=NAME sets it, -preset=
     * clears it, and without the switch a re-save keeps whatever the
     * site already had (a preset is configuration, not a secret). */
    if (presetGiven)
    {
        if (!storedPreset.empty())
        {
            std::string presetError;
            if (!mPresets.Load(presetError))
            {
                console.Error(presetError);
                mErrors++;
                return false;
            }
            const TransferPreset * preset = mPresets.Find(storedPreset);
            if (preset == NULL)
            {
                console.Error(Texts::WrongArguments("savesession",
                    Texts::Translate(
                        "There is no transfer preset named '{name}' in '{path}'; "
                        "create it with 'savepreset' first.",
                        {{"name", storedPreset}, {"path", mPresets.Path()}})));
                mErrors++;
                return false;
            }
            session.preset = preset->name;
        }
        else
        {
            session.preset.clear();
        }
    }
    else
    {
        const StoredSession * previous = mSessions.Find(name);
        session.preset = previous != NULL ? previous->preset : std::string();
    }
    /*
     * The proxy of this site. '-rawsettings' changes it, an open connection
     * brings the proxy it connected through, and a re-save with neither
     * keeps what the site was stored with - a proxy password this machine
     * cannot decrypt included, so that an unrelated save does not destroy
     * it (the same rule the session password follows).
     */
    if (!connected)
    {
        const StoredSession * previous = mSessions.Find(name);
        if (previous != NULL)
        {
            session.proxy = previous->proxy;
            session.proxyPasswordRaw = previous->proxyPasswordRaw;
            session.proxyError = previous->proxyError;
            session.tunnel = previous->tunnel;
            session.tunnelPasswordRaw = previous->tunnelPasswordRaw;
            session.tunnelPassphraseRaw = previous->tunnelPassphraseRaw;
            session.tunnelError = previous->tunnelError;
            session.gssapi = previous->gssapi;
        }
    }
    if (!rawSettings.empty())
    {
        std::string rawError;
        /* The settings land on a session built from what is being stored,
         * so the ones this build applies join the site and the rest is
         * refused by name - never stored and dropped at open time. */
        SessionOptions scratch = SessionStore::ToSessionOptions(session,
            SessionOptions());
        if (!ApplyRawSettings(rawSettings, scratch, rawError))
        {
            console.Error(Texts::WrongArguments("savesession", rawError));
            mErrors++;
            return false;
        }
        session.proxy = scratch.proxy;
        session.ftp = scratch.ftp;
        session.tls = scratch.tls;
        session.s3 = scratch.s3;
        session.tunnel = scratch.tunnel;
        session.gssapi = scratch.gssapi;
        for (const RawSetting & setting : rawSettings)
        {
            const std::string key = ToLower(setting.first);
            if (key == "tunnelpassword" || key == "tunnelpasswordplain")
                session.tunnelPasswordRaw.clear();
            if (key == "tunnelpassphrase" || key == "tunnelpassphraseplain")
                session.tunnelPassphraseRaw.clear();
        }
        if (!session.tunnel.enabled)
        {
            session.tunnel.password.clear();
            session.tunnel.keyPassphrase.clear();
            session.tunnelPasswordRaw.clear();
            session.tunnelPassphraseRaw.clear();
        }
        if (session.tunnelPasswordRaw.empty() && session.tunnelPassphraseRaw.empty())
            session.tunnelError.clear();
        /* What the switch states replaces the stored value, so a
         * ciphertext nobody could read does not survive it. */
        session.proxyPasswordRaw.clear();
        session.proxyError.clear();
    }
    /*
     * The port of a site nobody gave one for. The session defaults carry
     * the SSH port, and a site stored from them with '-protocol=ftp' or
     * '-protocol=s3' used to keep it: 'savesession mirror -host=h
     * -protocol=ftp' then 'open mirror' spoke FTP to port 22. 'open
     * ftp://h' already ignores the SSH default for such a scheme, so the
     * stored site follows the same rule and takes the port of its own
     * protocol - the implicit-TLS one when '-rawsettings Ftps=1' asks for
     * it, which is why this comes after the raw settings. A port given
     * explicitly, or the one an open connection really uses, is kept.
     */
    if (!portGiven && (!connected || protocolGiven) && session.portNumber == 22)
    {
        const int protocolDefault = SessionDefaultPort(session.protocol,
            session.tls.ftpsMode);
        if (protocolDefault != 22)
        {
            session.portNumber = protocolDefault;
        }
    }
    if (savePassword)
    {
        /* An explicit '-password=SECRET' wins; otherwise the password the
         * run already knows - from '-password=', from LINSCP_PASSWORD, or
         * from the open connection - is the one stored. The graphical
         * client passes its password through the environment so that it
         * never appears on a command line another user could read, and
         * 'savesession <name> -password' is how it asks for that value
         * to be stored without stating it again. */
        session.password = passwordGiven ? explicitPassword : options.password;
        if (session.password.empty())
        {
            console.Error(Texts::WrongArguments("savesession",
                Texts::Translate(
                    "The password of this connection is not known (it was typed or "
                    "taken from a key or an agent), so it cannot be stored.")));
            mErrors++;
            return false;
        }
    }
    else
    {
        const StoredSession * previous = mSessions.Find(name);
        if (previous != NULL && previous->name == name &&
            previous->passwordStored && previous->password.empty() &&
            !previous->passwordRaw.empty())
        {
            /*
             * An encrypted password this machine cannot decrypt is not
             * silently dropped by an unrelated re-save: keep the value
             * exactly as it is until the key file is back. (Once it
             * decrypts again, 'savesession <name>' without -password
             * clears it, as documented.)
             */
            session.passwordStored = true;
            session.passwordRaw = previous->passwordRaw;
            session.passwordError = previous->passwordError;
        }
    }

    std::string error;
    if (session.tunnel.enabled && !ValidateSessionSettings(
            SessionStore::ToSessionOptions(session, SessionOptions()), error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    if (!mSessions.AddOrUpdate(session, error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    if (!mSessions.Save(error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    console.Status(Texts::Translate(
        "Stored session '{name}' for {protocol}://{user}@{host}{location}.",
        {{"name", name}, {"protocol", session.protocol},
        {"user", session.userName}, {"host", session.hostName},
        {"location", mSessions.Path().empty() ? std::string() :
        std::string(" in ") + mSessions.Path()}}));
    if (!session.password.empty())
    {
        console.Status(Texts::Translate(
            "Warning: the password was stored encrypted in the session "
            "file{location}. It is readable by this account only; remove it "
            "with 'savesession {name}' after connecting with a key or an "
            "agent.",
            {{"location", mSessions.KeyPath().empty() ? std::string() :
            std::string(" under '") + mSessions.KeyPath() + "'"},
            {"name", name}}));
    }
    return true;
}

bool Script::RemoveStoredSessionEntry(const std::vector<std::string> & args)
{
    Console & console = Console::Instance();
    if (args.size() == 2 && ToLower(args[0]) == "-folder")
    {
        std::string error;
        const int removed = mSessions.RemoveFolder(args[1], error);
        if (removed == 0)
        {
            console.Error(error);
            mErrors++;
            return false;
        }
        if (!mSessions.Save(error))
        {
            console.Error(error);
            mErrors++;
            return false;
        }
        console.Status(Texts::Translate(
            "Removed {count} stored session(s) in folder '{folder}'.",
            {{"count", std::to_string(removed)}, {"folder", args[1]}}));
        return true;
    }
    if (args.size() != 1)
    {
        console.Error(Texts::WrongArguments("rmsession",
            Texts::Translate("Syntax: rmsession [-folder] <name>.")));
        mErrors++;
        return false;
    }
    if (args[0].size() > 1 && args[0][args[0].size() - 1] == '/')
    {
        std::string error;
        const int removed = mSessions.RemoveFolder(args[0], error);
        if (removed == 0)
        {
            console.Error(error);
            mErrors++;
            return false;
        }
        if (!mSessions.Save(error))
        {
            console.Error(error);
            mErrors++;
            return false;
        }
        console.Status(Texts::Translate(
            "Removed {count} stored session(s) in folder '{folder}'.",
            {{"count", std::to_string(removed)}, {"folder", args[0]}}));
        return true;
    }
    std::string error;
    if (!mSessions.Remove(args[0], error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    if (!mSessions.Save(error))
    {
        console.Error(error);
        mErrors++;
        return false;
    }
    console.Status(Texts::Translate(
        "Removed the stored session '{name}'.", {{"name", args[0]}}));
    return true;
}

bool Script::RemoveRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    std::vector<std::string> files;
    bool onlyFile = false;
    bool versionIdGiven = false;
    std::string versionId;
    for (size_t i = 0; i < args.size(); i++)
    {
        if (args[i] == "-onlyfile")
        {
            onlyFile = true;
            continue;
        }
        if (args[i] == "-versionid=" || StartsWith(args[i], "-versionid="))
        {
            if (versionIdGiven)
            {
                return SwitchError("rm", Texts::Translate(
                    "Give '-versionid' only once."));
            }
            versionId = args[i].substr(strlen("-versionid="));
            if (versionId.empty())
            {
                return SwitchError("rm", Texts::Translate(
                    "The value of '-versionid' cannot be empty."));
            }
            versionIdGiven = true;
            continue;
        }
        files.push_back(args[i]);
    }
    if (!CheckNameOperands("rm", files))
    {
        return false;
    }
    if (files.empty())
    {
        Console::Instance().Error(Texts::WrongArguments("rm",
            Texts::Translate("Syntax: rm [-onlyfile] [-versionid=ID] <file(s)>")));
        mErrors++;
        return false;
    }
    if (versionIdGiven)
    {
        if (ToLower(mSession.Options().protocol) != "s3")
        {
            return SwitchError("rm", Texts::Translate(
                "'-versionid' is available only for S3 object versions."));
        }
        if (onlyFile || files.size() != 1 || HasWildcard(files[0]))
        {
            return SwitchError("rm", Texts::Translate(
                "'-versionid' needs one exact S3 object path; '-onlyfile', "
                "wildcards and multiple paths are not supported."));
        }
        const std::string path = ResolveRemotePath(mRemoteDirectory, files[0]);
        if (mConfirm)
        {
            const ConfirmationResult confirmation = ConfirmDestructiveAction(
                Texts::Translate("Delete S3 version '{version}' of '{path}'?",
                    {{"version", versionId}, {"path", path}}));
            if (confirmation != ConfirmationResult::Accepted)
            {
                if (confirmation == ConfirmationResult::Unavailable)
                {
                    mErrors++;
                    return false;
                }
                return true;
            }
        }
        std::string error;
        if (S3Client::RemoveVersion(mSession.Options(), path, versionId,
                error) != 0)
        {
            Console::Instance().Error(Texts::RemoteError("remove", path, error));
            mErrors++;
            return false;
        }
        {
            /* An exact-version removal is an 'rm' of the object in the
             * XML log; the version it removed is in the group name (the
             * command line), the format having no element for it. */
            XmlParams params;
            params.push_back(std::make_pair("filename", path));
            Console::Instance().XmlAction("rm", params, true);
        }
        Console::Instance().Status(Texts::Translate(
            "Removed S3 object version '{version}' of '{path}'.",
            {{"version", versionId}, {"path", path}}));
        return true;
    }

    bool ok = true;
    for (size_t i = 0; i < files.size(); i++)
    {
        std::vector<std::string> paths;
        std::string error;
        if (!ExpandRemote(files[i], paths, error))
        {
            Console::Instance().Error(Texts::RemoteError("read", files[i], error));
            mErrors++;
            ok = false;
            continue;
        }
        if (paths.empty())
        {
            if (mFailOnNoMatch)
            {
                Console::Instance().Error(Texts::RemoteError("find", files[i],
                    "No matching files."));
                mErrors++;
                ok = false;
            }
            else
            {
                Console::Instance().Status(Texts::Translate(
                    "No file matching '{pattern}' found.",
                    {{"pattern", files[i]}}));
            }
            continue;
        }
        for (size_t n = 0; n < paths.size(); n++)
        {
            if (onlyFile)
            {
                LscpAttrs attrs = {};
                if (RemoteStat(paths[n], &attrs, error) == LSCP_SFTP_STAT_EXISTS &&
                    (attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
                    (attrs.permissions & 0040000) != 0)
                {
                    Console::Instance().Status(Texts::Translate(
                        "Skipped the directory '{path}' (-onlyfile).",
                        {{"path", paths[n]}}));
                    continue;
                }
            }
            if (mConfirm)
            {
                ConfirmationResult confirmation = ConfirmDestructiveAction(
                    Texts::Translate("Delete remote file '{path}'?", {{"path", paths[n]}}));
                if (confirmation != ConfirmationResult::Accepted)
                {
                    if (confirmation == ConfirmationResult::Unavailable)
                    {
                        mErrors++;
                        ok = false;
                    }
                    continue;
                }
            }
            if (RemoteRemove(paths[n], error) != 0)
            {
                Console::Instance().Error(Texts::RemoteError("remove", paths[n],
                    error));
                mErrors++;
                ok = false;
            }
        }
    }
    return ok;
}

bool Script::RemoveRemoteDirectory(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.empty())
    {
        Console::Instance().Error(Texts::WrongArguments("rmdir",
            Texts::Translate("Syntax: rmdir <directory> [<directory2> ...]")));
        mErrors++;
        return false;
    }
    if (!CheckNameOperands("rmdir", args))
    {
        return false;
    }
    bool ok = true;
    for (size_t i = 0; i < args.size(); i++)
    {
        std::string path = ResolveRemotePath(mRemoteDirectory, args[i]);
        if (mConfirm)
        {
            ConfirmationResult confirmation = ConfirmDestructiveAction(
                Texts::Translate("Delete remote directory '{path}'?", {{"path", path}}));
            if (confirmation != ConfirmationResult::Accepted)
            {
                if (confirmation == ConfirmationResult::Unavailable)
                {
                    mErrors++;
                    ok = false;
                }
                continue;
            }
        }
        std::string error;
        if (RemoteRemoveDir(path, error) != 0)
        {
            Console::Instance().Error(Texts::RemoteError("remove the directory",
                path, error));
            mErrors++;
            ok = false;
        }
    }
    return ok;
}

bool Script::MakeRemoteDirectory(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    /* The ordinary mkdir keeps upstream's single-directory semantics. The
     * explicit -parents form is useful to Linux desktop drops: each upload
     * can create its own destination tree, including on a task retry. */
    const bool parents = args.size() == 2 && args[0] == "-parents";
    if ((parents && args[1].empty()) ||
        (!parents && (args.size() != 1 || args[0].empty() || args[0][0] == '-')))
    {
        Console::Instance().Error(Texts::WrongArguments("mkdir",
            Texts::Translate("Syntax: mkdir [-parents] <directory>")));
        mErrors++;
        return false;
    }
    std::string path = ResolveRemotePath(mRemoteDirectory, args[parents ? 1 : 0]);
    std::string error;
    if (parents ? !CreateRemoteDirectoryRecursive(path, error) :
                  RemoteMakeDir(path, -1, error) != 0)
    {
        Console::Instance().Error(Texts::RemoteError("create the directory", path,
            error));
        mErrors++;
        return false;
    }
    return true;
}

bool Script::MoveRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() < 2)
    {
        Console::Instance().Error(Texts::WrongArguments("mv",
            Texts::Translate("Syntax: mv <source> [ <source>... ] <target>")));
        mErrors++;
        return false;
    }
    if (!CheckNameOperands("mv", args))
    {
        return false;
    }
    std::string error;
    const std::string to = ResolveRemotePath(mRemoteDirectory, args.back());
    std::vector<std::string> sources(args.begin(), args.end() - 1);
    /* With several sources the target must be an existing directory,
     * exactly like upstream 'mv'. */
    if (sources.size() > 1)
    {
        LscpAttrs targetAttrs = {};
        const int targetStat = RemoteStat(to, &targetAttrs, error);
        const bool targetIsDir = targetStat == LSCP_SFTP_STAT_EXISTS &&
            (targetAttrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
            (targetAttrs.permissions & 0040000) != 0;
        if (!targetIsDir)
        {
            Console::Instance().Error(Texts::WrongArguments("mv",
                Texts::Translate(
                    "When several files are moved at once, the target must be an "
                    "existing directory: '{path}' is not.", {{"path", to}})));
            mErrors++;
            return false;
        }
    }
    bool ok = true;
    for (size_t i = 0; i < sources.size(); i++)
    {
        std::string from = ResolveRemotePath(mRemoteDirectory, sources[i]);
        /* Moving into a directory target keeps the source name, unless
         * the target names the file itself. */
        std::string target = to;
        if (sources.size() > 1)
        {
            target = JoinRemotePath(to, RemoteFileName(from));
        }
        else
        {
            LscpAttrs targetAttrs = {};
            const int targetStat = RemoteStat(target, &targetAttrs, error);
            if (targetStat == LSCP_SFTP_STAT_EXISTS &&
                (targetAttrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
                (targetAttrs.permissions & 0040000) != 0)
            {
                target = JoinRemotePath(target, RemoteFileName(from));
            }
        }
        if (mConfirm)
        {
            LscpAttrs existing = {};
            const int targetStat = RemoteStat(target, &existing, error);
            if (targetStat == LSCP_SFTP_STAT_ERROR)
            {
                Console::Instance().Error(Texts::RemoteError("inspect target",
                    target, error));
                mErrors++;
                ok = false;
                continue;
            }
            if (targetStat == LSCP_SFTP_STAT_EXISTS)
            {
                ConfirmationResult confirmation = ConfirmDestructiveAction(
                    Texts::Translate("Overwrite remote file '{path}'?", {{"path", target}}));
                if (confirmation != ConfirmationResult::Accepted)
                {
                    if (confirmation == ConfirmationResult::Unavailable)
                    {
                        mErrors++;
                        ok = false;
                    }
                    continue;
                }
            }
        }
        if (RemoteRename(from, target, error) != 0)
        {
            Console::Instance().Error(Texts::RemoteError("move", from, error));
            mErrors++;
            ok = false;
        }
    }
    return ok;
}

/* ------------------------------------------------------------------ *
 * Remote copy (cp), symbolic links (ln), checksums, exec and copyid    *
 * ------------------------------------------------------------------ */

namespace {

/* A scratch name for streamed copies and checksum fallbacks, made
 * unique with the process id and a counter. */
std::string MakeTempPath(const char * suffix)
{
    static unsigned long counter = 0;
    const std::string dir = TempDirectory();
    if (dir.empty())
    {
        return std::string();
    }
    for (unsigned int attempt = 0; attempt < 64; attempt++)
    {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "%s/linscp-%ld-%s-%lu",
            dir.c_str(), static_cast<long>(getpid()), suffix, ++counter);
        const std::string path(buffer);
        FILE * probe = fopen(path.c_str(), "wx");
        if (probe != NULL)
        {
            fclose(probe);
            remove(path.c_str());
            return path;
        }
    }
    return std::string();
}

/* Joins the arguments of a command back into one command line, keeping
 * what quoting survived the split. */
std::string JoinCommandWords(const std::vector<std::string> & args)
{
    std::string command;
    for (size_t i = 0; i < args.size(); i++)
    {
        if (i > 0)
        {
            command += " ";
        }
        if (args[i].find(' ') != std::string::npos)
        {
            command += "\"" + args[i] + "\"";
        }
        else
        {
            command += args[i];
        }
    }
    return command;
}

/* The remote checksum algorithm names the server side understands. */
std::string ServerChecksumAlgorithm(const std::string & requested)
{
    std::string lowered;
    for (size_t i = 0; i < requested.size(); i++)
    {
        const char c = static_cast<char>(tolower(
            static_cast<unsigned char>(requested[i])));
        if (c != '-' && c != '_')
        {
            lowered += c;
        }
    }
    if (lowered == "sha256") return "sha-256";
    if (lowered == "sha1") return "sha-1";
    if (lowered == "md5") return "md5";
    if (lowered == "crc32") return "crc32";
    return std::string();
}

} // namespace

int Script::RemoteSymlink(const std::string & target,
    const std::string & linkPath, std::string & error)
{
    error.clear();
    if (UseNativeScp(mSession.Options().protocol))
    {
        /* The rcp protocol carries no way to make a link, but the shell
         * this session runs its commands in has one: 'ln -s'. */
        if (!ScpClient::MakeSymlink(mSession.Options(), target, linkPath, error))
        {
            return -1;
        }
        return 0;
    }
    if (!UseNativeSftp(mSession.Options().protocol))
    {
        error = Texts::Translate(
            "Creating symbolic links needs the native SFTP backend or an "
            "SCP session; the '{protocol}' protocol cannot do it.",
            {{"protocol", mSession.Options().protocol}});
        return -1;
    }
    if (lscp_sftp_symlink(target.c_str(), linkPath.c_str()) != 0)
    {
        error = lscp_sftp_error();
        return -1;
    }
    return 0;
}

int Script::RemoteStreamCopy(const std::string & from, const std::string & to,
    std::string & error)
{
    /* Copy through this client: download to a scratch file, upload it,
     * remove it. Works with every backend, including curl. */
    const std::string temp = MakeTempPath("copy");
    if (temp.empty())
    {
        error = Texts::Translate("Cannot create a temporary file for the copy.");
        return -1;
    }
    unsigned long long size = 0;
    if (RemoteGet(from, temp, 0, false, &size, NULL, NULL, error) != 0)
    {
        remove(temp.c_str());
        return -1;
    }
    const int result = RemotePut(temp, to, -1, 0, false, &size, NULL, NULL, error);
    remove(temp.c_str());
    return result;
}

bool Script::CopyRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() < 2)
    {
        Console::Instance().Error(Texts::WrongArguments("cp",
            Texts::Translate("Syntax: cp <source> [ <source>... ] <target>")));
        mErrors++;
        return false;
    }
    if (!CheckNameOperands("cp", args))
    {
        return false;
    }

    /* The last argument is the target; everything before it is copied. */
    std::vector<std::string> sourceArgs(args.begin(), args.end() - 1);
    const std::string targetArg = args.back();
    const std::string target = ResolveRemotePath(mRemoteDirectory, targetArg);

    LscpAttrs targetAttrs = {};
    std::string error;
    const int targetStat = RemoteStat(target, &targetAttrs, error);
    if (targetStat == LSCP_SFTP_STAT_ERROR)
    {
        Console::Instance().Error(Texts::RemoteError("inspect target", target,
            error));
        mErrors++;
        return false;
    }
    const bool targetExists = targetStat == LSCP_SFTP_STAT_EXISTS;
    const bool targetIsDir = targetExists &&
        (targetAttrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
        (targetAttrs.permissions & 0040000) != 0;

    /* Expand every source mask into paths. */
    std::vector<std::string> sources;
    bool expansionFailed = false;
    for (size_t i = 0; i < sourceArgs.size(); i++)
    {
        std::vector<std::string> expanded;
        if (!ExpandRemote(sourceArgs[i], expanded, error))
        {
            Console::Instance().Error(Texts::RemoteError("read", sourceArgs[i],
                error));
            mErrors++;
            expansionFailed = true;
            continue;
        }
        if (expanded.empty())
        {
            Console::Instance().Error(Texts::RemoteError("find", sourceArgs[i],
                "No matching files."));
            mErrors++;
            expansionFailed = true;
            continue;
        }
        for (size_t n = 0; n < expanded.size(); n++)
        {
            sources.push_back(expanded[n]);
        }
    }
    if (expansionFailed || sources.empty())
    {
        return false;
    }
    if (sources.size() > 1 && targetExists && !targetIsDir)
    {
        Console::Instance().Error(Texts::RemoteError("copy to", target,
            "A directory is required when copying multiple files."));
        mErrors++;
        return false;
    }

    bool any = false;
    bool ok = true;
    for (size_t i = 0; i < sources.size(); i++)
    {
        LscpAttrs sourceAttrs = {};
        const int sourceStat = RemoteStat(sources[i], &sourceAttrs, error);
        const bool sourceIsDir = sourceStat == LSCP_SFTP_STAT_EXISTS &&
            (sourceAttrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
            (sourceAttrs.permissions & 0040000) != 0;

        const std::string destination = (targetIsDir || sources.size() > 1) ?
            JoinRemotePath(target, RemoteFileName(sources[i])) : target;

        if (sourceIsDir)
        {
            if (!CopyRemoteTree(sources[i], destination))
            {
                ok = false;
                continue;
            }
            any = true;
            continue;
        }

        if (!CopyRemoteTree(sources[i], destination))
        {
            ok = false;
            continue;
        }
        any = true;
    }
    return any && ok;
}

/* Copies one file or a whole directory tree to one exact destination
 * path; the multi-source handling lives in CopyRemote. */
bool Script::CopyRemoteTree(const std::string & from, const std::string & to)
{
    std::string error;
    LscpAttrs attrs = {};
    const int statRes = RemoteStat(from, &attrs, error);
    const bool isDir = statRes == LSCP_SFTP_STAT_EXISTS &&
        (attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
        (attrs.permissions & 0040000) != 0;

    if (!isDir)
    {
        return CopyRemoteOneFile(from, to);
    }

    if (!CreateRemoteDirectoryRecursive(to, error))
    {
        Console::Instance().Error(Texts::RemoteError("create the directory",
            to, error));
        mErrors++;
        return false;
    }
    std::vector<SyncEntry> entries;
    if (!ListRemoteEntries(from, entries, error))
    {
        Console::Instance().Error(Texts::RemoteError("read directory", from,
            error));
        mErrors++;
        return false;
    }
    bool ok = true;
    for (size_t n = 0; n < entries.size(); n++)
    {
        if (!CopyRemoteTree(JoinRemotePath(from, entries[n].name),
                JoinRemotePath(to, entries[n].name)))
        {
            ok = false;
        }
    }
    return ok;
}

/* Copies one file to one exact destination path. */
bool Script::CopyRemoteOneFile(const std::string & from,
    const std::string & to)
{
    std::string error;
    if (mConfirm)
    {
        LscpAttrs existing = {};
        const int statRes = RemoteStat(to, &existing, error);
        if (statRes == LSCP_SFTP_STAT_ERROR)
        {
            Console::Instance().Error(Texts::RemoteError("inspect target", to,
                error));
            mErrors++;
            return false;
        }
        if (statRes == LSCP_SFTP_STAT_EXISTS)
        {
            const ConfirmationResult confirmation = ConfirmDestructiveAction(
                Texts::Translate("Overwrite remote file '{path}'?", {{"path", to}}));
            if (confirmation != ConfirmationResult::Accepted)
            {
                if (confirmation == ConfirmationResult::Unavailable)
                {
                    mErrors++;
                }
                return confirmation != ConfirmationResult::Unavailable;
            }
        }
    }

    if (UseNativeSftp(mSession.Options().protocol))
    {
        const int result = lscp_sftp_copy(from.c_str(), to.c_str());
        if (result == 0)
        {
            XmlLogCopy(from, to, true, std::string());
            Console::Instance().Status(Texts::Translate(
                "Copied '{from}' to '{to}' on the server.",
                {{"from", from}, {"to", to}}));
            return true;
        }
        if (result == -1)
        {
            Console::Instance().Error(Texts::RemoteError("copy", from,
                lscp_sftp_error()));
            mErrors++;
            XmlLogCopy(from, to, false, lscp_sftp_error());
            return false;
        }
        Console::Instance().Status(Texts::Translate(
            "The server cannot copy files by itself; copying through this "
            "client."));
    }
    else
    {
        const int result = ProtocolClient::Copy(mSession.Options(), from, to,
            error);
        if (result == 0)
        {
            XmlLogCopy(from, to, true, std::string());
            Console::Instance().Status(Texts::Translate(
                "Copied '{from}' to '{to}' on the server.",
                {{"from", from}, {"to", to}}));
            return true;
        }
        if (result < 0)
        {
            Console::Instance().Error(Texts::RemoteError("copy", from, error));
            mErrors++;
            XmlLogCopy(from, to, false, error);
            return false;
        }
    }

    if (RemoteStreamCopy(from, to, error) != 0)
    {
        Console::Instance().Error(Texts::RemoteError("copy", from, error));
        mErrors++;
        XmlLogCopy(from, to, false, error);
        return false;
    }
    XmlLogCopy(from, to, true, std::string());
    Console::Instance().Status(Texts::Translate("Copied '{from}' to '{to}'.",
        {{"from", from}, {"to", to}}));
    return true;
}

bool Script::LinkRemote(const std::vector<std::string> & args, const char * name)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() != 2)
    {
        Console::Instance().Error(Texts::WrongArguments(name,
            Texts::Translate("Syntax: {command} <target> <link>",
                {{"command", std::string(name)}})));
        mErrors++;
        return false;
    }
    const std::string target = ResolveRemotePath(mRemoteDirectory, args[0]);
    const std::string linkPath = ResolveRemotePath(mRemoteDirectory, args[1]);
    std::string error;
    if (RemoteSymlink(target, linkPath, error) != 0)
    {
        Console::Instance().Error(Texts::RemoteError("create the symbolic link",
            linkPath, error));
        mErrors++;
        return false;
    }
    Console::Instance().Status(Texts::Translate(
        "Created '{link}' pointing at '{target}'.",
        {{"link", linkPath}, {"target", target}}));
    return true;
}

bool Script::ChecksumRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() != 2)
    {
        Console::Instance().Error(Texts::WrongArguments("checksum",
            Texts::Translate(
                "Syntax: checksum <algorithm> <file> (algorithm: sha-256, "
                "sha-1, md5 or crc32)")));
        mErrors++;
        return false;
    }
    const std::string requested = args[0];
    const std::string path = ResolveRemotePath(mRemoteDirectory, args[1]);

    /* A directory has no checksum of its own. */
    LscpAttrs attrs = {};
    std::string error;
    if (RemoteStat(path, &attrs, error) != LSCP_SFTP_STAT_EXISTS)
    {
        Console::Instance().Error(Texts::RemoteError("read the attributes of",
            path, error));
        mErrors++;
        return false;
    }
    if ((attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
        (attrs.permissions & 0040000) != 0)
    {
        Console::Instance().Error(Texts::WrongArguments("checksum",
            Texts::Translate("'{path}' is a directory, not a file.",
                {{"path", path}})));
        mErrors++;
        return false;
    }

    std::string hex;
    std::string note;
    std::string failure;
    if (!RemoteChecksumFile(path, requested, hex, note, failure))
    {
        Console::Instance().Error(failure);
        mErrors++;
        XmlParams params;
        params.push_back(std::make_pair("filename", path));
        params.push_back(std::make_pair("algorithm", requested));
        Console::Instance().XmlAction("checksum", params, false, failure);
        return false;
    }
    if (!note.empty())
    {
        Console::Instance().Status(note);
    }
    {
        XmlParams params;
        params.push_back(std::make_pair("filename", path));
        params.push_back(std::make_pair("algorithm", requested));
        params.push_back(std::make_pair("checksum", hex));
        Console::Instance().XmlAction("checksum", params, true);
    }
    Console::Instance().WriteLine(hex + " " + path);
    return true;
}

/*
 * WebDAV locks and dead properties: 'lock' takes an exclusive write lock on
 * one path, 'unlock' releases it, and 'property' reads or writes one dead
 * property. Upstream's WebDAV backend sends no LOCK, UNLOCK or PROPPATCH at
 * all, so these are LinSCP extensions; a server that does not implement one
 * answers 405 and the command prints that instead of reporting a write
 * that was never protected. The token of a lock this session holds travels
 * with every later upload, delete and move of that path (the If header),
 * which is what makes the server enforce the lock.
 */
bool Script::LockRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    std::vector<std::string> paths;
    int timeout = 0;
    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string lower = ToLower(args[i]);
        if (StartsWith(lower, "-timeout="))
        {
            const std::string value = args[i].substr(strlen("-timeout="));
            bool digits = !value.empty() && value.size() <= 9;
            for (size_t j = 0; digits && j < value.size(); j++)
            {
                digits = value[j] >= '0' && value[j] <= '9';
            }
            long parsed = 0;
            if (digits)
            {
                /* Bounded above: twenty digits are all digits, but they
                 * are not a number of seconds atoi() can hold - the
                 * conversion was undefined behaviour rather than a
                 * refused switch. */
                parsed = strtol(value.c_str(), NULL, 10);
                digits = parsed > 0 && parsed <= 2147483647L;
            }
            if (!digits)
            {
                Console::Instance().Error(Texts::WrongArguments("lock",
                    Texts::Translate(
                        "The value of '-timeout' is the number of seconds the server "
                        "should keep the lock for.")));
                mErrors++;
                return false;
            }
            timeout = static_cast<int>(parsed);
        }
        else if (args[i].size() > 1 && args[i][0] == '-')
        {
            Console::Instance().Error(Texts::WrongArguments("lock",
                Texts::Translate("Unknown switch '{switch}'.", {{"switch", args[i]}})));
            mErrors++;
            return false;
        }
        else
        {
            paths.push_back(args[i]);
        }
    }
    if (paths.size() != 1)
    {
        Console::Instance().Error(Texts::WrongArguments("lock",
            Texts::Translate("Syntax: lock <file> [-timeout=SECONDS]")));
        mErrors++;
        return false;
    }
    const std::string path = ResolveRemotePath(mRemoteDirectory, paths[0]);
    std::string token;
    std::string error;
    if (!ProtocolClient::DavLock(mSession.Options(), path, timeout, token, error))
    {
        Console::Instance().Error(Texts::RemoteError("lock", path, error));
        mErrors++;
        return false;
    }
    mSession.SetDavLock(path, token);
    Console::Instance().WriteLine(Texts::Translate(
        "Locked {path} with token {token}.", {{"path", path}, {"token", token}}));
    return true;
}

bool Script::UnlockRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() != 1)
    {
        Console::Instance().Error(Texts::WrongArguments("unlock",
            Texts::Translate(
                "Syntax: unlock <file> (releases the lock 'lock <file>' took)")));
        mErrors++;
        return false;
    }
    const std::string path = ResolveRemotePath(mRemoteDirectory, args[0]);
    const std::string token = mSession.DavLockFor(path);
    if (token.empty())
    {
        Console::Instance().Error(Texts::WrongArguments("unlock",
            Texts::Translate(
                "This session holds no lock on '{path}'; take one with "
                "'lock {command}' first.",
                {{"path", path}, {"command", args[0]}})));
        mErrors++;
        return false;
    }
    std::string error;
    if (!ProtocolClient::DavUnlock(mSession.Options(), path, token, error))
    {
        Console::Instance().Error(Texts::RemoteError("unlock", path, error));
        mErrors++;
        return false;
    }
    mSession.ClearDavLock(path);
    Console::Instance().WriteLine(Texts::Translate("Unlocked {path}.",
        {{"path", path}}));
    return true;
}

bool Script::DavPropertyCommand(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    std::vector<std::string> paths;
    std::string getName;
    std::string setName;
    std::string setValue;
    bool getGiven = false;
    bool setGiven = false;
    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string lower = ToLower(args[i]);
        if (StartsWith(lower, "-get="))
        {
            getName = args[i].substr(strlen("-get="));
            getGiven = true;
        }
        else if (StartsWith(lower, "-set="))
        {
            const std::string pair = args[i].substr(strlen("-set="));
            const size_t equals = pair.find('=');
            if (equals == std::string::npos)
            {
                Console::Instance().Error(Texts::WrongArguments("property",
                    Texts::Translate("'-set' takes NAME=VALUE.")));
                mErrors++;
                return false;
            }
            setName = pair.substr(0, equals);
            setValue = pair.substr(equals + 1);
            setGiven = true;
        }
        else if (args[i].size() > 1 && args[i][0] == '-')
        {
            Console::Instance().Error(Texts::WrongArguments("property",
                Texts::Translate("Unknown switch '{switch}'.", {{"switch", args[i]}})));
            mErrors++;
            return false;
        }
        else
        {
            paths.push_back(args[i]);
        }
    }
    if (paths.size() != 1 || getGiven == setGiven || (getGiven && getName.empty()))
    {
        Console::Instance().Error(Texts::WrongArguments("property",
            Texts::Translate(
                "Syntax: property <file> -get=NAME | property <file> "
                "-set=NAME=VALUE")));
        mErrors++;
        return false;
    }
    const std::string path = ResolveRemotePath(mRemoteDirectory, paths[0]);
    std::string error;
    if (setGiven)
    {
        if (!ProtocolClient::DavSetProperty(mSession.Options(), path, setName,
            setValue, error))
        {
            Console::Instance().Error(Texts::RemoteError("set the property of",
                path, error));
            mErrors++;
            return false;
        }
        Console::Instance().WriteLine(Texts::PropertySet(setName, path));
        return true;
    }
    std::string value;
    bool found = false;
    if (!ProtocolClient::DavGetProperty(mSession.Options(), path, getName, value,
        found, error))
    {
        Console::Instance().Error(Texts::RemoteError("read the property of",
            path, error));
        mErrors++;
        return false;
    }
    if (!found)
    {
        /* Not an error: the server answered that the property is not set,
         * which is an answer about the file and not a failure. */
        Console::Instance().WriteLine(getName + " is not set on " + path + ".");
        return true;
    }
    Console::Instance().WriteLine(getName + "=" + value);
    return true;
}

/*
 * WebDAV ETag preconditions: 'etag <file> -match=ETAG' sets an If-Match
 * precondition (write only if the server's ETag matches); 'etag <file>
 * -nomatch=ETAG' sets If-None-Match (write only if the ETag differs);
 * 'etag <file> -get' retrieves and prints the current ETag;
 * 'etag <file> -clear' removes any precondition for that path.
 *
 * This is a LinSCP extension. Upstream's WebDAV backend has no ETag-based
 * conditional writes. The preconditions protect against lost-update when
 * two clients edit the same file independently of session lock tokens.
 */
bool Script::EtagCommand(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    std::vector<std::string> paths;
    std::string matchEtag;
    std::string nomatchEtag;
    bool getGiven = false;
    bool clearGiven = false;
    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string lower = ToLower(args[i]);
        if (StartsWith(lower, "-match="))
        {
            matchEtag = DavEntityTag(args[i].substr(strlen("-match=")));
        }
        else if (StartsWith(lower, "-nomatch="))
        {
            nomatchEtag = DavEntityTag(args[i].substr(strlen("-nomatch=")));
        }
        else if (lower == "-get")
        {
            getGiven = true;
        }
        else if (lower == "-clear")
        {
            clearGiven = true;
        }
        else if (args[i].size() > 1 && args[i][0] == '-')
        {
            Console::Instance().Error(Texts::WrongArguments("etag",
                Texts::Translate("Unknown switch '{switch}'.", {{"switch", args[i]}})));
            mErrors++;
            return false;
        }
        else
        {
            paths.push_back(args[i]);
        }
    }
    if (paths.size() != 1)
    {
        Console::Instance().Error(Texts::WrongArguments("etag",
            Texts::Translate(
                "Syntax: etag <file> -match=ETAG | -nomatch=ETAG | -get | -clear")));
        mErrors++;
        return false;
    }
    /* '*' is the "only where there is nothing yet" of a bare
     * If-None-Match header, and the If header this client states a
     * precondition in has no room for it: RFC 4918 reads a condition as a
     * state token or an entity tag, so a quoted "*" would be a tag no
     * resource carries and the condition would hold on every write,
     * guarding nothing while looking like a guard. Refused instead. */
    if (matchEtag == "*" || nomatchEtag == "*")
    {
        Console::Instance().Error(Texts::WrongArguments("etag",
            Texts::Translate(
                "'*' is not an entity tag. Give the tag 'etag <file> -get' "
                "prints, which a path that is not there answers with.")));
        mErrors++;
        return false;
    }
    const int actions = (matchEtag.empty() ? 0 : 1) +
        (nomatchEtag.empty() ? 0 : 1) + (getGiven ? 1 : 0) + (clearGiven ? 1 : 0);
    if (actions != 1)
    {
        Console::Instance().Error(Texts::WrongArguments("etag",
            Texts::Translate(
                "Give exactly one of -match=ETAG, -nomatch=ETAG, -get or -clear.")));
        mErrors++;
        return false;
    }

    const std::string path = ResolveRemotePath(mRemoteDirectory, paths[0]);
    std::string error;

    if (getGiven)
    {
        /* Only a WebDAV server has an ETag to answer with. Every other
         * protocol is told so instead of being handed a value nothing on
         * that transport would ever compare a write against. */
        const std::string & protocol = mSession.Options().protocol;
        if (!ProtocolClient::IsDavProtocol(protocol))
        {
            Console::Instance().WriteLine(Texts::EtagNotAvailable(protocol));
            return true;
        }
        std::string etag;
        bool pathMissing = false;
        if (!ProtocolClient::DavGetEtag(mSession.Options(), path, etag,
            pathMissing, error))
        {
            Console::Instance().Error(Texts::RemoteError("get the ETag of",
                path, error));
            mErrors++;
            return false;
        }
        if (!etag.empty())
        {
            Console::Instance().WriteLine(etag);
        }
        else
        {
            /* Two different answers, and only one of them is about the
             * path: a server that sends no getetag has not said the file
             * is missing. */
            Console::Instance().WriteLine(pathMissing ? Texts::NoEtag(path)
                : Texts::NoEtagReported(path));
        }
        return true;
    }

    /* A precondition is recorded with the session that set it, the way a
     * lock token is: the value belongs to the connection that read the
     * resource, and one remembered afterwards would guard nothing. */
    if (!ProtocolClient::IsDavProtocol(mSession.Options().protocol))
    {
        /* Refused rather than recorded: a precondition a transport cannot
         * check would leave the user believing a write is conditional. */
        Console::Instance().Error(Texts::EtagNotAvailable(
            mSession.Options().protocol));
        mErrors++;
        return false;
    }

    if (clearGiven)
    {
        mSession.ClearDavEtag(path);
        Console::Instance().WriteLine(Texts::EtagCleared(path));
        return true;
    }

    /* Set the precondition. */
    mSession.SetDavEtag(path, matchEtag, nomatchEtag);
    Console::Instance().WriteLine(Texts::EtagSet(
        matchEtag.empty() ? "If-None-Match" : "If-Match",
        matchEtag.empty() ? nomatchEtag : matchEtag, path));
    return true;
}

/*
 * One remote file's checksum, as lowercase hexadecimal. The server computes
 * it when the backend can ask it to; otherwise the file is downloaded to a
 * temporary file and hashed here, which is the same fallback the 'checksum'
 * command has always used. 'note' receives the line a command tells the user
 * about which of the two happened, and stays empty when the server answered.
 *
 * The synchronization planner calls this for '-criteria=checksum', where
 * there is no command to print to: it collects the note itself and says it
 * once.
 */
bool Script::RemoteChecksumFile(const std::string & path,
    const std::string & algorithm, std::string & hex, std::string & note,
    std::string & error)
{
    /* 1. Ask the server, when the backend can. */
    if (UseNativeSftp(mSession.Options().protocol))
    {
        const std::string serverAlgorithm = ServerChecksumAlgorithm(algorithm);
        if (!serverAlgorithm.empty())
        {
            char used[64];
            char digest[LSCP_HASH_HEX_SIZE];
            const int result = lscp_sftp_checksum(serverAlgorithm.c_str(),
                path.c_str(), used, sizeof(used), digest, sizeof(digest));
            if (result == 0)
            {
                hex = digest;
                return true;
            }
            if (result == -1)
            {
                error = Texts::RemoteError("calculate the checksum of", path,
                    lscp_sftp_error());
                return false;
            }
            note = "The server cannot calculate checksums; '" + algorithm +
                "' is computed from the downloaded file.";
        }
        else
        {
            note = "'" + algorithm + "' is not a server-side algorithm; it is "
                "computed from the downloaded file.";
        }
    }
    else
    {
        note = "The '" + mSession.Options().protocol + "' backend cannot run a "
            "server-side checksum; '" + algorithm + "' is computed from the "
            "downloaded file.";
    }

    /* 2. Fallback: hash the file as it is downloaded. */
    const std::string temp = MakeTempPath("sum");
    if (temp.empty())
    {
        error = Texts::Translate(
            "Cannot create a temporary file for the checksum.");
        return false;
    }
    unsigned long long size = 0;
    std::string transferError;
    if (RemoteGet(path, temp, 0, false, &size, NULL, NULL, transferError) != 0)
    {
        remove(temp.c_str());
        error = Texts::TransferFailed(path, transferError);
        return false;
    }
    char digest[LSCP_HASH_HEX_SIZE];
    const bool hashed = lscp_hash_file(algorithm.c_str(), temp.c_str(),
        digest, sizeof(digest)) == 0;
    remove(temp.c_str());
    if (!hashed)
    {
        error = Texts::RemoteError("calculate the checksum of", path,
            lscp_hash_error());
        return false;
    }
    hex = digest;
    return true;
}

bool Script::CallRemote(const std::vector<std::string> & args, const char * name)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.empty())
    {
        Console::Instance().Error(Texts::WrongArguments(name,
            Texts::Translate("Syntax: {command} <command>",
                {{"command", std::string(name)}})));
        mErrors++;
        return false;
    }
    const SessionOptions & options = mSession.Options();
    if (!UseNativeSftp(options.protocol) && !UseNativeScp(options.protocol))
    {
        Console::Instance().Error(Texts::WrongArguments(name,
            Texts::Translate(
                "Executing a command on the server needs an SSH (sftp:// or "
                "scp://) session, not '{protocol}'.",
                {{"protocol", options.protocol}})));
        mErrors++;
        return false;
    }
    const std::string command = JoinCommandWords(args);
    std::string error;
    bool ok;
    if (Console::Instance().IsActionLogOpen())
    {
        /* The XML log records what the command printed, stream by
         * stream, with its exit code: that is what a reader of the log
         * (upstream's own model of 'call') expects to find, so this run
         * captures instead of only printing. */
        Session::ExecCaptured captured;
        ok = Session::ExecRemoteCaptured(options, command, error, captured);
        XmlParams params;
        params.push_back(std::make_pair("command", command));
        params.push_back(std::make_pair("destination", mRemoteDirectory));
        if (!captured.output.empty())
        {
            params.push_back(std::make_pair("output", captured.output));
        }
        if (!captured.errorOutput.empty())
        {
            params.push_back(std::make_pair("erroroutput",
                captured.errorOutput));
        }
        if (captured.exitCode != INT_MAX)
        {
            params.push_back(std::make_pair("exitcode",
                std::to_string(captured.exitCode)));
        }
        Console::Instance().XmlAction("call", params, ok,
            ok ? std::string() : error);
    }
    else
    {
        ok = Session::ExecRemote(options, command, error);
    }
    if (!ok)
    {
        Console::Instance().Error(Texts::RemoteError("run the command on",
            options.hostName, error.empty() ? "the connection failed" : error));
        mErrors++;
        return false;
    }
    return true;
}

namespace {

/* The part of an authorized_keys line that says which key it is: the
 * algorithm and the base64 blob, without the trailing comment. Two lines
 * with the same identity are the same key, however differently they are
 * commented. */
std::string KeyIdentity(const std::string & line)
{
    size_t end = 0;
    for (int field = 0; field < 2; field++)
    {
        while (end < line.size() && line[end] == ' ')
        {
            end++;
        }
        while (end < line.size() && line[end] != ' ')
        {
            end++;
        }
    }
    return line.substr(0, end);
}

} // namespace

/*
 * 'copyid [<privatekey>]': installs the public half of a key on the server,
 * which is upstream's 'copyid'. OpenSSH key files are read with libssh;
 * PPK v2/v3 public sections are parsed natively. The line is appended unless
 * the file already
 * holds the key. The permissions matter to sshd, which ignores a key under a
 * group-writable directory, so both are set as the server expects.
 */
bool Script::CopyPublicKey(const std::vector<std::string> & args)
{
    std::string keyFile;
    std::string passphrase;
    bool haveKeyArg = false;
    for (size_t i = 0; i < args.size(); i++)
    {
        const std::string lower = ToLower(args[i]);
        if (StartsWith(lower, "-passphrase="))
        {
            passphrase = args[i].substr(strlen("-passphrase="));
        }
        else if (!args[i].empty() && args[i][0] == '-')
        {
            return SwitchError("copyid", Texts::Translate(
                "Syntax: copyid [<keyfile>] [-passphrase=<passphrase>]; "
                "without a file the private key of the session is used."));
        }
        else if (!haveKeyArg)
        {
            keyFile = args[i];
            haveKeyArg = true;
        }
        else
        {
            return SwitchError("copyid", Texts::Translate(
                "Syntax: copyid [<keyfile>] [-passphrase=<passphrase>]; "
                "without a file the private key of the session is used."));
        }
    }
    if (!RequireConnection())
    {
        return false;
    }
    const SessionOptions & options = mSession.Options();
    if (!UseNativeSftp(options.protocol) && !UseNativeScp(options.protocol))
    {
        return SwitchError("copyid", Texts::Translate(
            "Installing a public key needs an SSH (sftp:// or scp://) "
            "session, not '{protocol}'.", {{"protocol", options.protocol}}));
    }
    if (!haveKeyArg)
    {
        keyFile = options.privateKeyFile;
    }
    if (passphrase.empty())
    {
        passphrase = options.keyPassphrase;
    }
    if (keyFile.empty())
    {
        return SwitchError("copyid", Texts::Translate(
            "There is no private key: connect with -privatekey=<file>, "
            "or give the key file to the command."));
    }
    const std::string expandedKeyFile = ExpandTilde(keyFile);
    std::string keyLine;
    std::string error;
    for (int attempt = 0; attempt < 3; ++attempt)
    {
        if (PublicKeyAuthorizedLine(expandedKeyFile, keyLine, error, passphrase))
            break;
        if (!IsPpkKeyFile(expandedKeyFile) ||
            error.find("integrity check failed") == std::string::npos ||
            !passphrase.empty() || !Console::Instance().IsInteractive() || attempt == 2)
            return SwitchError("copyid", error);
        if (!Console::Instance().ReadPassword(
                Texts::Translate("PPK key passphrase: "), passphrase))
            return SwitchError("copyid", error);
    }
    if (keyLine.empty()) return SwitchError("copyid", error);
    if (mHomeDirectory.empty())
    {
        return SwitchError("copyid", Texts::Translate(
            "The home directory of the session is not known, so "
            "~/.ssh/authorized_keys cannot be located."));
    }

    const std::string sshDirectory = JoinRemotePath(mHomeDirectory, ".ssh");
    const std::string authorizedKeys = JoinRemotePath(sshDirectory, "authorized_keys");

    /* Create the directory when the server has none yet. */
    LscpAttrs attrs = {};
    std::string statError;
    if (RemoteStat(sshDirectory, &attrs, statError) != LSCP_SFTP_STAT_EXISTS)
    {
        std::string makeError;
        if (RemoteMakeDir(sshDirectory, 0700, makeError) != 0)
        {
            return SwitchError("copyid", Texts::Translate("Cannot create '{path}': {reason}",
                {{"path", sshDirectory}, {"reason", makeError}}));
        }
        Console::Instance().Status(Texts::Translate("Created '{path}'.",
            {{"path", sshDirectory}}));
    }

    /* Keep the keys that are installed already; a repeated 'copyid' must not
     * grow the file, and a server with a full authorized_keys is a common
     * leftover of a previous WinSCP run. */
    const std::string temp = MakeTempPath("authkeys");
    if (temp.empty())
    {
        return SwitchError("copyid", Texts::Translate(
            "Cannot create a temporary file for the authorized keys."));
    }
    bool installed = false;
    bool failed = false;
    std::vector<std::string> kept;
    statError.clear();
    if (RemoteStat(authorizedKeys, &attrs, statError) == LSCP_SFTP_STAT_EXISTS)
    {
        std::string getError;
        if (RemoteGet(authorizedKeys, temp, 0, false, NULL, NULL, NULL, getError) != 0)
        {
            remove(temp.c_str());
            return SwitchError("copyid", Texts::Translate("Cannot read '{path}': {reason}",
                {{"path", authorizedKeys}, {"reason", getError}}));
        }
        RestrictFileToUser(temp);
        FILE * file = fopen(temp.c_str(), "rb");
        if (file != NULL)
        {
            char buffer[16384];
            while (fgets(buffer, sizeof(buffer), file) != NULL)
            {
                std::string line = buffer;
                while (!line.empty() && (line[line.size() - 1] == '\n' ||
                    line[line.size() - 1] == '\r'))
                {
                    line.erase(line.size() - 1);
                }
                if (line.empty())
                {
                    continue;
                }
                kept.push_back(line);
                if (KeyIdentity(line) == KeyIdentity(keyLine))
                {
                    installed = true;
                }
            }
            fclose(file);
        }
    }

    if (installed)
    {
        remove(temp.c_str());
        Console::Instance().Status(Texts::Translate(
            "The key is already installed in '{path}'.",
            {{"path", authorizedKeys}}));
        return true;
    }

    FILE * file = fopen(temp.c_str(), "wb");
    if (file == NULL)
    {
        return SwitchError("copyid", Texts::Translate(
            "Cannot write a temporary file for the authorized keys."));
    }
    RestrictFileToUser(temp);
    for (size_t i = 0; i < kept.size(); i++)
    {
        fprintf(file, "%s\n", kept[i].c_str());
    }
    fprintf(file, "%s\n", keyLine.c_str());
    const bool writeBad = fflush(file) != 0 || ferror(file) != 0;
    if (fclose(file) != 0 || writeBad)
    {
        remove(temp.c_str());
        return SwitchError("copyid", Texts::Translate(
            "Cannot write a temporary file for the authorized keys."));
    }

    std::string putError;
    if (RemotePut(temp, authorizedKeys, 0600, 0, false, NULL, NULL, NULL,
        putError) != 0)
    {
        failed = true;
        Console::Instance().Error(Texts::TransferFailed(authorizedKeys, putError));
    }
    remove(temp.c_str());
    if (failed)
    {
        mErrors++;
        return false;
    }
    Console::Instance().Status(Texts::Translate(
        "Installed the public key of '{key}' in '{path}'.",
        {{"key", keyFile}, {"path", authorizedKeys}}));
    return true;
}

bool Script::ApplyRemotePermissions(const std::string & path, const std::string & mode,
    bool recursive, unsigned long long & changed)
{
    LscpAttrs attrs = {};
    std::string error;
    if (RemoteStat(path, &attrs, error) != LSCP_SFTP_STAT_EXISTS)
    {
        Console::Instance().Error(Texts::RemoteError("read the attributes of", path, error));
        mErrors++;
        return false;
    }
    const bool hasPermissions = (attrs.flags & LSCP_ATTR_PERMISSIONS) != 0;
    const bool isDirectory = hasPermissions && (attrs.permissions & 0040000) != 0;
    const unsigned long current = hasPermissions ? static_cast<unsigned long>(attrs.permissions & 07777) : 0;

    unsigned long wanted = 0;
    std::string modeError;
    if (!ParsePermissions(mode, current, isDirectory, wanted, modeError))
    {
        Console::Instance().Error(Texts::Translate("'{path}': {reason}",
            {{"path", path}, {"reason", modeError}}));
        mErrors++;
        return false;
    }
    /* Only the permission bits change; the file type and the set-id bits
     * that the mode does not mention stay as they are. */
    const unsigned long result = hasPermissions ?
        ((attrs.permissions & ~07777UL) | (wanted & 07777)) : (wanted & 07777);

    bool ok = true;
    if (RemoteSetPermissions(path, (int)result, error) != 0)
    {
        Console::Instance().Error(Texts::RemoteError("change the permissions of",
            path, error));
        mErrors++;
        ok = false;
    }
    else
    {
        changed++;
    }

    if (ok && recursive && isDirectory)
    {
        LscpNames * names = NULL;
        std::string dirError;
        if (!RemoteListDir(path, names, dirError))
        {
            Console::Instance().Error(Texts::RemoteError("read directory", path, dirError));
            mErrors++;
            return false;
        }
        for (int i = 0; i < names->count; i++)
        {
            const char * rawName = names->names[i].filename;
            if (rawName == NULL)
            {
                continue;
            }
            const std::string name(rawName);
            if (name == "." || name == "..")
            {
                continue;
            }
            const unsigned long type = names->names[i].attrs.permissions & 0170000;
            if (type == 0120000)
            {
                continue;   /* a symbolic link is left alone */
            }
            if (!ApplyRemotePermissions(JoinRemotePath(path, name), mode, true, changed))
            {
                ok = false;
            }
        }
        RemoteFreeNames(names);
    }
    return ok;
}

bool Script::ChangeRemotePermissions(const std::vector<std::string> & args)
{
    /* The mode is checked before the connection, so that a typo is reported
     * even when nothing can be changed, and no half-parsed command reaches
     * the server. */
    /* The switch may come before or after the mode. */
    bool recursive = false;
    std::vector<std::string> rest;
    for (size_t i = 0; i < args.size(); i++)
    {
        if (args[i] == "-recursive" || args[i] == "-r")
        {
            recursive = true;
        }
        else
        {
            rest.push_back(args[i]);
        }
    }
    if (rest.size() < 2)
    {
        Console::Instance().Error(Texts::WrongArguments("chmod",
            Texts::Translate("Syntax: chmod <permissions> <file(s)> [-recursive]")));
        mErrors++;
        return false;
    }
    const std::string mode = rest[0];

    /* Check the mode before anything is touched, so that a typo cannot
     * change the first file and then fail on the second. */
    unsigned long probe = 0;
    std::string modeError;
    if (!ParsePermissions(mode, 0644, false, probe, modeError))
    {
        Console::Instance().Error(Texts::WrongArguments("chmod",
            Texts::Translate(
                "'{mode}' is not a valid mode: {reason}. Use an octal number "
                "such as 644 or an expression such as u+x.",
                {{"mode", mode}, {"reason", modeError}})));
        mErrors++;
        return false;
    }
    if (!RequireConnection())
    {
        return false;
    }

    bool ok = true;
    unsigned long long changed = 0;
    for (size_t i = 1; i < rest.size(); i++)
    {
        std::vector<std::string> paths;
        std::string error;
        if (!ExpandRemote(rest[i], paths, error))
        {
            Console::Instance().Error(Texts::RemoteError("read", rest[i], error));
            mErrors++;
            ok = false;
            continue;
        }
        if (paths.empty())
        {
            Console::Instance().Error(Texts::RemoteError("find", rest[i],
                "No matching files."));
            mErrors++;
            ok = false;
            continue;
        }
        for (size_t n = 0; n < paths.size(); n++)
        {
            if (!ApplyRemotePermissions(paths[n], mode, recursive, changed))
            {
                ok = false;
            }
        }
    }
    if (recursive)
    {
        Console::Instance().WriteLine(std::to_string(changed) +
            (changed == 1 ? " file changed." : " files changed."));
    }
    return ok;
}

/*
 * 'attr' is this client's key/value breakdown of a remote file's
 * attributes - the machine-readable form the graphical client parses.
 * It used to be what 'stat' printed; upstream's 'stat' prints a single
 * listing line instead, which is why the listing line is StatRemote
 * below and this detail stayed available under its own name.
 */
bool Script::AttrRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() != 1)
    {
        Console::Instance().Error(Texts::WrongArguments("attr", "Syntax: attr <file>"));
        mErrors++;
        return false;
    }
    std::string path = ResolveRemotePath(mRemoteDirectory, args[0]);
    LscpAttrs attrs;
    std::string error;
    const int statResult = RemoteStat(path, &attrs, error);
    if (statResult != LSCP_SFTP_STAT_EXISTS)
    {
        /* A path that is not there is an answer, and an empty reason next
         * to it reads like the client gave up without asking. */
        if (statResult == LSCP_SFTP_STAT_MISSING && error.empty())
        {
            error = Texts::Translate("There is no such file or directory.");
        }
        Console::Instance().Error(Texts::RemoteError("read the attributes of", path,
            error));
        mErrors++;
        return false;
    }
    Console::Instance().WriteLine(Texts::Translate("Path:        {path}",
        {{"path", path}}));
    Console::Instance().WriteLine(Texts::Translate("Size:        {size}",
        {{"size", FormatSize(attrs.size)}}));
    Console::Instance().WriteLine(Texts::Translate("Permissions: {permissions}",
        {{"permissions", FormatPermissions(attrs.permissions)}}));
    Console::Instance().WriteLine(Texts::Translate("Modified:    {time}",
        {{"time", FormatFileTime(attrs.mtime)}}));
    if ((attrs.flags & LSCP_ATTR_SIZE) != 0)
    {
        Console::Instance().WriteLine(Texts::Translate("SizeBytes:   {size}",
            {{"size", std::to_string(attrs.size)}}));
    }
    if ((attrs.flags & LSCP_ATTR_ACMODTIME) != 0)
    {
        /* Seconds since the epoch, for a script or the graphical client
         * that wants to compare timestamps rather than read them. */
        Console::Instance().WriteLine(Texts::Translate("ModifiedEpoch: {time}",
            {{"time", std::to_string(attrs.mtime)}}));
        Console::Instance().WriteLine(Texts::Translate("AccessedEpoch: {time}",
            {{"time", std::to_string(attrs.atime)}}));
    }
    Console::Instance().WriteLine(Texts::Translate("Owner:       {owner}",
        {{"owner", std::string(attrs.flags & LSCP_ATTR_UIDGID ?
        std::to_string(attrs.uid) + ":" + std::to_string(attrs.gid) :
        std::string("unknown"))}}));
    return true;
}

/*
 * Upstream 'stat' prints the one listing line of the path - what 'ls -l'
 * shows for that entry. The attribute probe itself is AttrRemote's.
 */
bool Script::StatRemote(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return false;
    }
    if (args.size() != 1)
    {
        Console::Instance().Error(Texts::WrongArguments("stat", Texts::Translate("Syntax: stat <file>")));
        mErrors++;
        return false;
    }
    std::string path = ResolveRemotePath(mRemoteDirectory, args[0]);
    LscpAttrs attrs;
    std::string error;
    const int statResult = RemoteStat(path, &attrs, error);
    XmlParams params;
    params.push_back(std::make_pair("filename", path));
    if (statResult != LSCP_SFTP_STAT_EXISTS)
    {
        /* A path that is not there is an answer, and an empty reason next
         * to it reads like the client gave up without asking. */
        if (statResult == LSCP_SFTP_STAT_MISSING && error.empty())
        {
            error = Texts::Translate("There is no such file or directory.");
        }
        Console::Instance().Error(Texts::RemoteError("read the attributes of", path,
            error));
        mErrors++;
        Console::Instance().XmlActionFile("stat", params, XmlFileInfo(),
            false, error);
        return false;
    }
    Console::Instance().XmlActionFile("stat", params,
        XmlFileInfoFromAttrs(std::string(), attrs), true);
    LscpName entry = LscpName();
    entry.attrs = attrs;
    PrintRemoteEntry(RemoteFileName(path), entry, true);
    return true;
}

/*
 * WinSCP's "Open Terminal" (Ctrl+P): an interactive shell on the server
 * that the session is connected to. This client's SSH core offers the
 * SFTP subsystem only, so the shell comes from the system ssh client in
 * a terminal window, which is also what makes the command useful in a
 * script file. The terminal program is picked by the platform layer
 * (LINSCP_TERMINAL overrides it on POSIX).
 */
void Script::OpenTerminal(const std::vector<std::string> & args)
{
    if (!RequireConnection())
    {
        return;
    }
    if (!args.empty())
    {
        Console::Instance().Error(Texts::WrongArguments("terminal",
            Texts::Translate("The command takes no arguments.")));
        mErrors++;
        return;
    }

    const SessionOptions & options = mSession.Options();
    if (!UseNativeSftp(options.protocol) && !UseNativeScp(options.protocol))
    {
        Console::Instance().Error(Texts::Translate(
            "An interactive terminal is only available for SSH (sftp:// or "
            "scp://) sessions, not for '{protocol}'.",
            {{"protocol", options.protocol}}));
        mErrors++;
        return;
    }

    std::string userName = mSession.UserName();
    if (userName.empty())
    {
        userName = options.userName;
    }

    /* A PPK-format key file cannot be read by the system ssh client, so the
     * terminal can only use the agent (or ask for a password). */
    const std::string key = ExpandTilde(options.privateKeyFile);
    if (key.size() >= 4)
    {
        std::string extension = key.substr(key.size() - 4);
        for (size_t i = 0; i < extension.size(); i++)
        {
            extension[i] = static_cast<char>(tolower(static_cast<unsigned char>(extension[i])));
        }
        if (extension == ".ppk")
        {
            Console::Instance().LogEvent(Texts::Translate(
                "The PPK-format key file '{key}' is not passed to the system ssh "
                "client; the terminal will use the agent or ask for a "
                "password.", {{"key", key}}));
        }
    }

    std::string error;
    std::string note;
    if (!LaunchTerminalForServer(userName, options.hostName, options.portNumber,
            key, error, &note))
    {
        Console::Instance().Error(error);
        mErrors++;
        return;
    }

    /* Which window the session got is worth one line: 'it opened a
     * terminal' followed by a blurry window, or by no window at all, is the
     * report a user cannot act on. */
    if (!note.empty())
    {
        Console::Instance().Status(note);
    }

    Console::Instance().WriteLine(Texts::Translate("Opened a terminal on {target}.",
        {{"target", userName.empty() ? options.hostName :
        userName + "@" + options.hostName}}));
}

bool Script::SetOption(const std::vector<std::string> & args)
{
    const std::string supported = Texts::Translate(
        "supported: echo, batch, confirm, resume, transfer, include, exclude, "
        "failonnomatch, synchdelete, reconnecttime, editor, editmaxsize, "
        "preset");
    if (args.empty())
    {
        /* 'option' with no name lists every option and its value, like
         * the upstream client. */
        const char * names[] = { "echo", "batch", "confirm", "resume",
            "transfer", "include", "exclude", "failonnomatch", "synchdelete",
            "reconnecttime", "editor", "editmaxsize", "preset" };
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        {
            std::vector<std::string> one;
            one.push_back(names[i]);
            SetOption(one);
        }
        return true;
    }
    std::string name = ToLower(args[0]);
    /*
     * Upstream looks an option name up in the same table as the commands,
     * so 'option synchdel on' and 'option e off' are as good as the full
     * names. An unknown name is left alone, so that the message at the end
     * of this function still says which option this build does not have.
     */
    if (name != "clear")
    {
        std::string resolved;
        if (!ResolveAbbreviation(OptionNames(), name, "option name", resolved))
        {
            return false;
        }
        if (!resolved.empty())
        {
            name = resolved;
        }
    }
    if (args.size() == 1)
    {
        if (name == "echo")
        {
            Console::Instance().Status(Texts::OptionValue("echo",
                mEchoCommands ? "on" : "off"));
            return true;
        }
        if (name == "confirm")
        {
            Console::Instance().Status(Texts::OptionValue("confirm",
                mConfirm ? "on" : "off"));
            return true;
        }
        if (name == "batch")
        {
            const char * value = mBatchMode == BatchMode::Abort ? "abort" :
                mBatchMode == BatchMode::Continue ? "continue" :
                mBatchMode == BatchMode::On ? "on" : "off";
            Console::Instance().Status(Texts::OptionValue("batch", value));
            return true;
        }
        if (name == "resume")
        {
            const char * value = mResumeMode == ResumeMode::On ? "on" :
                mResumeMode == ResumeMode::Off ? "off" : "automatic";
            Console::Instance().Status(Texts::OptionValue("resume", value));
            return true;
        }
        if (name == "transfer")
        {
            Console::Instance().Status(Texts::OptionValue("transfer",
                TransferModeName(mTransferMode)));
            return true;
        }
        if (name == "preset")
        {
            Console::Instance().Status(Texts::OptionValue("preset",
                mActivePresetName.empty() ? std::string("off") :
                 mActivePresetName));
            return true;
        }
        if (name == "include")
        {
            std::string masks;
            for (size_t i = 0; i < mOptionMask.include.size(); i++)
            {
                if (i != 0)
                {
                    masks += ";";
                }
                masks += mOptionMask.include[i].text;
            }
            Console::Instance().Status(Texts::OptionValue("include",
                masks.empty() ? std::string("(none)") : masks));
            return true;
        }
        if (name == "exclude")
        {
            std::string masks;
            for (size_t i = 0; i < mOptionMask.exclude.size(); i++)
            {
                if (i != 0)
                {
                    masks += ";";
                }
                masks += mOptionMask.exclude[i].text;
            }
            Console::Instance().Status(Texts::OptionValue("exclude",
                masks.empty() ? std::string("(none)") : masks));
            return true;
        }
        if (name == "failonnomatch")
        {
            Console::Instance().Status(Texts::OptionValue("failonnomatch",
                mFailOnNoMatch ? "on" : "off"));
            return true;
        }
        if (name == "synchdelete")
        {
            Console::Instance().Status(Texts::OptionValue("synchdelete",
                mSyncDeleteDefault ? "on" : "off"));
            return true;
        }
        if (name == "reconnecttime")
        {
            Console::Instance().Status(Texts::OptionValue("reconnecttime",
                mReconnectSeconds > 0 ? std::to_string(mReconnectSeconds) :
                std::string("off")));
            return true;
        }
        if (name == "editor")
        {
            Console::Instance().Status(Texts::OptionValue("editor",
                mEditor.empty() ? std::string("(from LINSCP_EDITOR, VISUAL or EDITOR)")
                : mEditor));
            return true;
        }
        if (name == "editmaxsize")
        {
            Console::Instance().Status(Texts::OptionValue("editmaxsize",
                std::to_string(mEditMaxSize)));
            return true;
        }
    }
    if (args.size() != 2)
    {
        Console::Instance().Error(Texts::WrongArguments("option",
            Texts::Translate("Syntax: option [<name> [<value>]] ({options})",
                {{"options", supported}})));
        mErrors++;
        return false;
    }
    std::string value = ToLower(args[1]);
    /*
     * The value of an option that comes from a fixed vocabulary is resolved
     * the same way ('option batch cont'), but only for those options: a file
     * mask, an editor command and a size are free text and must never be
     * second-guessed.
     */
    if (name != "include" && name != "exclude" && name != "editor" &&
        name != "editmaxsize" && name != "reconnecttime" && name != "preset")
    {
        std::vector<std::string> vocabulary = ToggleNames();
        if (name == "batch")
        {
            vocabulary = BatchModeNames();
        }
        else if (name == "transfer")
        {
            vocabulary = TransferModeNames();
        }
        else if (name == "resume")
        {
            vocabulary = ResumeModeNames();
        }
        std::string resolved;
        if (!ResolveAbbreviation(vocabulary, value,
            "value of the option '" + name + "'", resolved))
        {
            return false;
        }
        if (!resolved.empty())
        {
            value = resolved;
        }
    }
    const bool isOn = value == "on";
    const bool isToggle = isOn || value == "off";
    if (name == "echo" || name == "failonnomatch" || name == "synchdelete" ||
        name == "confirm")
    {
        if (!isToggle)
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                "The value of '" + name + "' must be 'on' or 'off'."));
            mErrors++;
            return false;
        }
        if (name == "echo")
        {
            mEchoCommands = isOn;
        }
        else if (name == "failonnomatch")
        {
            mFailOnNoMatch = isOn;
        }
        else if (name == "synchdelete")
        {
            mSyncDeleteDefault = isOn;
        }
        else
        {
            mConfirm = isOn;
        }
        return true;
    }
    if (name == "resume")
    {
        if (value == "on")
        {
            mResumeMode = ResumeMode::On;
        }
        else if (value == "off")
        {
            mResumeMode = ResumeMode::Off;
        }
        else if (value == "automatic")
        {
            mResumeMode = ResumeMode::Automatic;
        }
        else
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                Texts::Translate("The value of 'resume' must be on, off or automatic.")));
            mErrors++;
            return false;
        }
        return true;
    }
    if (name == "transfer")
    {
        TransferMode mode;
        if (!ParseTransferMode(value, mode))
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                "The value of 'transfer' must be binary, ascii or automatic."));
            mErrors++;
            return false;
        }
        mTransferMode = mode;
        return true;
    }
    if (name == "preset")
    {
        /* The value keeps its case: preset names are free text. */
        if (value == "off")
        {
            mActivePresetName.clear();
            mPresetOff = true;
            return true;
        }
        std::string loadError;
        if (!mPresets.Load(loadError))
        {
            Console::Instance().Error(loadError);
            mErrors++;
            return false;
        }
        const TransferPreset * preset = mPresets.Find(args[1]);
        if (preset == NULL)
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                Texts::Translate(
                    "There is no transfer preset named '{name}' in '{path}'; "
                    "create it with 'savepreset'.",
                    {{"name", args[1]}, {"path", mPresets.Path()}})));
            mErrors++;
            return false;
        }
        mActivePresetName = preset->name;
        mPresetOff = false;
        return true;
    }
    if (name == "include" || name == "exclude")
    {
        /* 'clear' resets the whole persistent mask. */
        if (value == "clear")
        {
            mOptionMask = FileMask();
            mOptionMaskUsed = false;
            return true;
        }
        FileMask parsed;
        std::string maskError;
        if (!parsed.Parse(args[1], maskError))
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                maskError));
            mErrors++;
            return false;
        }
        if (!parsed.include.empty() && !parsed.exclude.empty())
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                "Do not use '|' in 'option " + name +
                "'; set 'include' or 'exclude' separately."));
            mErrors++;
            return false;
        }
        /* Setting one half replaces the whole mask, like upstream:
         * 'option exclude *.bak' forgets a previous 'option include'. */
        FileMask combined;
        if (name == "include")
        {
            combined.include = parsed.include;
        }
        else
        {
            combined.exclude = !parsed.exclude.empty() ?
                parsed.exclude : parsed.include;
        }
        mOptionMask = combined;
        mOptionMaskUsed = true;
        return true;
    }
    if (name == "reconnecttime")
    {
        if (value == "off")
        {
            mReconnectSeconds = 0;
            return true;
        }
        int seconds = 0;
        for (size_t i = 0; i < args[1].size(); i++)
        {
            if (args[1][i] < '0' || args[1][i] > '9')
            {
                seconds = -1;
                break;
            }
            seconds = seconds * 10 + (args[1][i] - '0');
            if (seconds > 3600)
            {
                break;
            }
        }
        if (seconds < 1 || seconds > 3600)
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                Texts::Translate(
                    "The value of 'reconnecttime' must be a number of seconds "
                    "from 1 to 3600, or 'off'.")));
            mErrors++;
            return false;
        }
        mReconnectSeconds = seconds;
        return true;
    }
    if (name == "batch")
    {
        if (value == "on")
        {
            mBatchMode = BatchMode::On;
        }
        else if (value == "abort")
        {
            mBatchMode = BatchMode::Abort;
        }
        else if (value == "continue")
        {
            mBatchMode = BatchMode::Continue;
        }
        else if (value == "off")
        {
            mBatchMode = BatchMode::Off;
        }
        else
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                Texts::Translate(
                    "The value of 'batch' must be 'on', 'off', 'abort' or 'continue'.")));
            mErrors++;
            return false;
        }
        mBatchConfigured = true;
        Console::Instance().SetBatchMode(mBatchMode != BatchMode::Off);
        return true;
    }
    if (name == "editor")
    {
        mEditor = args[1];
        return true;
    }
    if (name == "editmaxsize")
    {
        if (args[1].empty())
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                Texts::Translate("The value of 'editmaxsize' must be a number of bytes.")));
            mErrors++;
            return false;
        }
        unsigned long long bytes = 0;
        for (size_t i = 0; i < args[1].size(); i++)
        {
            if (args[1][i] < '0' || args[1][i] > '9')
            {
                Console::Instance().Error(Texts::WrongArguments("option",
                    Texts::Translate("The value of 'editmaxsize' must be a number of bytes.")));
                mErrors++;
                return false;
            }
            const unsigned long long digit =
                static_cast<unsigned long long>(args[1][i] - '0');
            if (bytes > ((1ULL << 40) - digit) / 10ULL)
            {
                Console::Instance().Error(Texts::WrongArguments("option",
                    "The value of 'editmaxsize' exceeds the maximum supported size (1 TiB)."));
                mErrors++;
                return false;
            }
            bytes = bytes * 10ULL + digit;
        }
        if (bytes == 0)
        {
            Console::Instance().Error(Texts::WrongArguments("option",
                Texts::Translate(
                    "The value of 'editmaxsize' must be a positive number of bytes.")));
            mErrors++;
            return false;
        }
        mEditMaxSize = bytes;
        return true;
    }
    Console::Instance().Error(Texts::WrongArguments("option",
        Texts::Translate("The option '{name}' is not supported by this build.",
            {{"name", args[0]}})));
    mErrors++;
    return false;
}

/*
 * The command an alias stands for, for the help of an alias; names that
 * are commands of their own come back unchanged.
 */
static std::string CanonicalCommandAlias(const std::string & name)
{
    static const struct
    {
        const char * alias;
        const char * target;
    } aliases[] = {
        { "!", "call" }, { "?", "help" }, { "del", "rm" },
        { "delsession", "rmsession" }, { "dir", "ls" }, { "end", "exit" },
        { "md", "mkdir" }, { "mget", "get" }, { "mput", "put" },
        { "quit", "exit" }, { "recv", "get" }, { "rename", "mv" },
        { "send", "put" }, { "sync", "synchronize" },
    };
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++)
    {
        if (name == aliases[i].alias)
        {
            return aliases[i].target;
        }
    }
    return name;
}

/* Help texts, kept as data so that 'help' can enumerate the commands the
 * way upstream enumerates its registered ones. Upstream keeps these in its
 * resource strings; this is the equivalent for the implemented subset,
 * close to the wording of the WinSCP documentation. */
namespace {
const struct ScriptCommandHelpEntry
{
    const char * name;
    const char * help;
} kScriptCommandHelps[] = {
        { "ascii", "ascii\n"
            "  Transfers files in ASCII mode: line endings are converted\n"
            "  (CRLF to LF when downloading, LF to CRLF when uploading)." },
        { "attr", "attr <file>\n"
            "  Prints path, size, permissions, modification time and owner\n"
            "  of a remote file, one key/value line each." },
        { "binary", "binary\n"
            "  Transfers files in binary mode (no conversion)." },
        { "bye", "bye\n"
            "  Ends the session and exits." },
        { "call", "call <command>\n"
            "  Executes a command on the server through the SSH 'exec'\n"
            "  channel and prints its output. '! <command>' is the same." },
        { "cd", "cd [ <directory> ]\n"
            "  Changes the remote working directory; without an argument\n"
            "  it goes to the home directory." },
        { "checksum", "checksum <algorithm> <file>\n"
            "  Calculates a checksum (sha-256, sha-1, md5 or crc32) of a\n"
            "  remote file, on the server when it can, locally otherwise." },
        { "chmod", "chmod <mode> <file> [ <file>... ] [ -recursive ]\n"
            "  Changes permissions of remote files. <mode> is octal\n"
            "  (644, 0700) or symbolic (u+x, go-w, a=r,go-w, u+s); with\n"
            "  -recursive everything below a directory is changed too,\n"
            "  symbolic links excepted." },
        { "close", "close [ <index> ]\n"
            "  Closes the open session, or the session at the 1-based\n"
            "  <index> (only one connection is open at a time)." },
        { "copyid", "copyid [ <keyfile> ]\n"
            "  Installs the public key of the private key in use (or of\n"
            "  <keyfile>) into ~/.ssh/authorized_keys on the server, so\n"
            "  that later connections need no password. Requires a SFTP\n"
            "  or SCP session and a key this build can read." },
        { "cp", "cp <source> [ <source>... ] <target>\n"
            "  Copies files on the server, server-side when it can,\n"
            "  streamed through this client otherwise." },
        { "echo", "echo <message>\n"
            "  Prints the message." },
        { "edit", "edit <file>\n"
            "  Downloads the file, opens it in the configured editor and\n"
            "  uploads it back when it changed." },
        { "exit", "exit\n"
            "  Ends the session and exits." },
        { "get", "get [ <switches> ] <file> [ <file>... ] [ <target> ]\n"
            "  Downloads files. Switches: -delete, -resume, -append,\n"
            "  -resumesupport=on|off|<KB>, -speed=<KB/s>, -neweronly,\n"
            "  -noneweronly, -latest, -preservetime, -preservetime=all,\n"
            "  -nopreservetime, -r, -transfer=binary|ascii|automatic,\n"
            "  -permissions[=<mode>], -nopermissions, -versionid=<ID>,\n"
            "  -rawtransfersettings[=<count>], -filemask=<mask>.\n"
            "  -latest transfers only the newest file the command named,\n"
            "  by the source's modification time.\n"
            "  For S3, -versionid downloads that exact object version; it\n"
            "  stages separately per version so resumes never mix versions.\n"
            "  Without a value, -permissions gives the downloaded file\n"
            "  the permissions of the remote one." },

        { "help", "help [ <command> ]\n"
            "  Prints the list of commands, or the help of one command." },
        { "keepuptodate", "keepuptodate [ <localdir> [ <remotedir> ] ]\n"
            "  Reflects local changes on the remote side, watching the local\n"
            "  tree with inotify. -interval=<seconds>, -count=<passes>,\n"
            "  -delete, -continue, -filemask=, -transfer=." },
        { "lcd", "lcd <directory>\n"
            "  Changes the local working directory." },
        { "lls", "lls [ <directory>[/<mask>] ]\n"
            "  Lists the local working directory." },
        { "ln", "ln <target> <link>\n"
            "  Creates a symbolic link on the server." },
        { "lpwd", "lpwd\n"
            "  Prints the local working directory." },
        { "ls", "ls [ <directory>[/<mask>] ]\n"
            "  Lists the remote directory (switches: -l, -a, -1)." },
        { "man", "man [ <command> ]\n"
            "  Same as 'help'." },
        { "mkdir", "mkdir [-parents] <directory>\n"
            "  Creates a remote directory. -parents creates missing parents\n"
            "  and accepts an existing directory (a LinSCP extension)." },
        { "mv", "mv <source> [ <source>... ] <target>\n"
            "  Moves or renames remote files; with several sources the\n"
            "  target must be an existing directory." },
        { "open", "open <site> [-hostkey=KEY] [-password=PWD] [-username=NAME]\n"
            "        [-privatekey=FILE] [-passphrase=PHR] [-clientcert=FILE]\n"
            "        [-timeout=SEC] [-implicit[=on|off]] [-explicit[=on|off]]\n"
            "        [-passive[=on|off]] [-sessionname=NAME]\n"
            "        [-rawsettings NAME=VALUE...]\n"
            "  Connects to a site given as a URL or a stored session name;\n"
            "  the switches apply to a stored site as well as to a URL.\n"
            "  -timeout is the server response timeout in seconds.\n"
            "  -implicit and -explicit choose the TLS mode of an FTP\n"
            "  session (implicit TLS uses port 990 when the URL names no\n"
            "  port); -passive turns the FTP data connection policy on or\n"
            "  off; -clientcert is the TLS client certificate file;\n"
            "  -sessionname is the name this connection is logged under.\n"
            "  -rawsettings sets session settings by upstream's names. This\n"
            "  build applies the proxy ones (ProxyMethod=None|SOCKS4|SOCKS5|\n"
            "  HTTP|Telnet|Cmd, ProxyHost, ProxyPort, ProxyUsername,\n"
            "  ProxyPassword, ProxyTelnetCommand, ProxyLocalCommand,\n"
            "  ProxyDNS=0|1|2, ProxyLocalhost=0|1, ProxyExcludeList), the FTP\n"
            "  engine's policy (FtpPasvMode=0|1, FtpForcePasvIp=0|1|2,\n"
            "  FtpUseMlsd=0|1|2, FtpAccount) and the TLS policy (Ftps=0|1|2|3,\n"
            "  MinTlsVersion, MaxTlsVersion, TlsCertificateFile,\n"
            "  TlsCertificateKeyFile, CaCertificateFile, CaCertificateDir,\n"
            "  PinnedPublicKey); any other setting is refused rather than\n"
            "  dropped." },
        { "option", "option [ <name> [ <value> ] ]\n"
            "  Shows or changes a setting: echo, batch, confirm, resume,\n"
            "  transfer, include, exclude, failonnomatch, synchdelete,\n"
            "  reconnecttime, editor, editmaxsize, preset. Without a name it\n"
            "  prints every setting; a name or a value may be abbreviated\n"
            "  as long as the abbreviation is unambiguous." },
        { "presets", "presets\n"
            "  Lists the transfer presets from the user configuration.\n"
            "  A preset is stored with 'savepreset <name> <setting>...'\n"
            "  (transfer=binary|ascii|automatic, preservetime=on|off|all,\n"
            "  neweronly, speed=<KB/s>, resumesupport=on|off|<KB>,\n"
            "  permissions=<octal>|off|fromfile, host=, user=, remotedir=,\n"
            "  localdir=, mask=); 'rmspreset <name>' removes one.\n"
            "  'option preset <name>' makes a preset the default for the\n"
            "  following transfer commands, 'option preset off' disables\n"
            "  presets for this session (even matching rules); a stored\n"
            "  site loads its own when it is opened." },
        { "put", "put [ <switches> ] <file> [ <file>... ] [ <target> ]\n"
            "  Uploads files; the switches of 'get' (on uploads,\n"
            "  -permissions without a value keeps the local file's own\n"
            "  mode on the server); -append adds to the remote file\n"
            "  instead of replacing it (native SFTP only, and not\n"
            "  together with -resume); -latest uploads only the newest\n"
            "  local file the command named." },
        { "pwd", "pwd\n"
            "  Prints the remote working directory." },
        { "rm", "rm [ -onlyfile ] [ -versionid=ID ] <file> [ <file>... ]\n"
            "  Deletes remote files (masks allowed); -onlyfile skips\n"
            "  directories. On S3, -versionid deletes just that version\n"
            "  (including a delete marker) instead of the current object." },
        { "rmdir", "rmdir <directory> [ <directory>... ]\n"
            "  Deletes empty remote directories." },
        { "rmsession", "rmsession <name>\n"
            "  Removes the stored session <name>." },
        { "rmspreset", "rmspreset <name>\n"
            "  Removes the transfer preset <name>; if it was active,\n"
            "  transfers go back to their own settings." },
        { "savepreset", "savepreset <name> <setting>[=<value>]...\n"
            "  Stores or updates a transfer preset; settings without a\n"
            "  value (neweronly) are switches. See 'help presets'." },
        { "savesession", "savesession <name> [ options ]\n"
            "  Stores the current session, or the one the options\n"
            "  describe, under <name>; -preset=NAME also stores the\n"
            "  transfer preset the site should load (-preset= clears it),\n"
            "  and -rawsettings NAME=VALUE... stores session settings with\n"
            "  it (the ones 'open -rawsettings' applies: proxy, FTP engine\n"
            "  and TLS policy; a proxy password is encrypted like a session\n"
            "  password)." },
        { "show", "show\n"
            "  Not available in this build: the connection runs the SFTP\n"
            "  subsystem, so remote shell commands cannot be shown." },
        { "session", "session [ <index> ]\n"
            "  Lists the open sessions and prints which one is active;\n"
            "  with a 1-based <index> it switches to that session." },
        { "sessions", "sessions [ NAME | list | export <file> | import <file> ]\n"
            "  Lists the stored sites, opens one by name, or exports and\n"
            "  imports the whole list." },
        { "etag", "etag <file> -match=ETAG | -nomatch=ETAG | -get | -clear\n"
            "  Records an ETag precondition for one WebDAV path with this\n"
            "  session: an upload, a delete or a move of that path then\n"
            "  sends it in the If header next to any lock token, so the\n"
            "  server refuses (412) a write over a version this client has\n"
            "  not seen instead of accepting it. '-get' prints the ETag the\n"
            "  server reports now and says so when the path is not there,\n"
            "  '-clear' forgets the precondition. Give exactly one of the\n"
            "  four. A protocol with no ETags is refused rather than left\n"
            "  believing a write is conditional." },
        { "lock", "lock <file> [-timeout=SECONDS]\n"
            "  Takes an exclusive WebDAV write lock on one file and\n"
            "  remembers its token: uploads, deletes and moves of that\n"
            "  path then carry it, so the server refuses a write the lock\n"
            "  should prevent instead of accepting it." },
        { "property", "property <file> -get=NAME | property <file> -set=NAME=VALUE\n"
            "  Reads or writes one WebDAV dead property of a file, in this\n"
            "  client's own namespace. '-get' prints 'NAME is not set' when\n"
            "  the server says the property does not exist." },
        { "stat", "stat <file>\n"
            "  Prints the listing line of a remote path, as ls -l shows\n"
            "  it. The key/value breakdown of attr stays available there." },
        { "synchronize", "synchronize local|remote|both [ <localdir> [ <remotedir> ] ]\n"
            "  [ -delete ] [-nodelete] [-mirror] [-preview]\n"
            "  [-criteria=time|size|checksum|either|both|none] [-filemask=<mask>]\n"
            "  [-transfer=binary|ascii|automatic] [-nonrecursive]\n"
            "  The criteria say what counts as a change: 'time' (the\n"
            "  default) copies a file the source has newer, 'size' one of\n"
            "  a different size, 'checksum' one whose contents differ and\n"
            "  'none' every file. 'either' and its synonym 'both' compare\n"
            "  the time and the size, and the three comparisons may also\n"
            "  be listed, as in -criteria=time,checksum. In the 'both'\n"
            "  direction the record of the previous synchronization\n"
            "  decides, so 'checksum' and 'none' are refused there." },
        { "symlink", "symlink <target> <link>\n"
            "  Same as 'ln'." },
        { "terminal", "terminal\n"
            "  Opens an interactive shell terminal on the server." },
        { "unlock", "unlock <file>\n"
            "  Releases the lock 'lock <file>' took in this session." },
        { "versions", "versions [ <object-or-prefix> ]\n"
            "  Lists S3 object versions and delete markers. An object path\n"
            "  lists that exact key; a bucket or trailing-slash prefix\n"
            "  lists every matching key. Results are paginated." },
};
}

/* The help of one command, in the language of this run, or an empty
 * string when the command has none. The text itself is the message in
 * the catalog, so the English wording is the key and the translation is
 * looked up by it; the usage line stays as it was written, because it
 * holds command and switch names. */
std::string Script::CommandHelp(const std::string & command)
{
    for (size_t i = 0; i < sizeof(kScriptCommandHelps) /
        sizeof(kScriptCommandHelps[0]); i++)
    {
        if (command == kScriptCommandHelps[i].name)
        {
            return Texts::Translate(kScriptCommandHelps[i].help);
        }
    }
    return std::string();
}

void Script::PrintHelp(const std::vector<std::string> & args)
{
    if (!args.empty())
    {
        for (size_t i = 0; i < args.size(); i++)
        {
            std::string help = CommandHelp(ToLower(args[i]));
            if (help.empty())
            {
                /* Aliases share the help of the command they stand for. */
                help = CommandHelp(CanonicalCommandAlias(ToLower(args[i])));
            }
            if (help.empty())
            {
                Console::Instance().Error(Texts::UnknownCommand(args[i]));
                mErrors++;
                continue;
            }
            Console::Instance().WriteLine(help);
        }
        return;
    }
    /* Upstream lists every registered command with a description in
     * 'name<7 spaces> description' columns; the description is the
     * second line of the per-command help text. */
    std::string output;
    for (size_t i = 0; i < sizeof(kScriptCommandHelps) /
        sizeof(kScriptCommandHelps[0]); i++)
    {
        const std::string help = Texts::Translate(kScriptCommandHelps[i].help);
        size_t summaryStart = help.find('\n');
        std::string summary = summaryStart == std::string::npos ?
            std::string() : help.substr(summaryStart + 1);
        while (!summary.empty() && (summary[0] == ' ' || summary[0] == '\t'))
        {
            summary.erase(0, 1);
        }
        if (summary.empty())
        {
            continue;
        }
        char prefix[16];
        snprintf(prefix, sizeof(prefix), "%-8s ", kScriptCommandHelps[i].name);
        output += std::string(prefix) + summary + "\n";
    }
    Console::Instance().WriteLine(output);
}

bool Script::ExecuteLine(const std::string & line)
{
    if (mExit)
    {
        return false;
    }
    /* 'option echo on' prints every command as it runs, so that a log
     * file shows what a script did. The -server loop must stay silent. */
    if (mEchoCommands && !mServerLoop)
    {
        Console::Instance().WriteLine(CensoredForLog(line));
    }
    const int before = mErrors;
    /* In the XML log a command is a '<group>' named by its (masked)
     * line: the operations it performed are its children, and a failure
     * ends it with a '<failure>' holding the errors it printed, masked
     * the same way before they are kept in a file. A reader following
     * the file knows the command is over when the group closes. */
    if (Console::Instance().IsActionLogOpen())
    {
        /* The line still carries the spacing around its ';' separator;
         * upstream names the group by the command itself. */
        std::string groupName = CensoredForLog(line);
        const size_t first = groupName.find_first_not_of(" \t");
        const size_t last = groupName.find_last_not_of(" \t");
        groupName = first == std::string::npos ? std::string() :
            groupName.substr(first, last - first + 1);
        Console::Instance().XmlBeginGroup(groupName);
    }
    const bool keepRunning = ExecuteCommand(line);
    mLastCommandFailed = mErrors != before;
    if (Console::Instance().IsActionLogOpen())
    {
        if (mLastCommandFailed)
        {
            std::vector<std::string> messages =
                Console::Instance().TakeActionErrors();
            for (size_t i = 0; i < messages.size(); i++)
            {
                messages[i] = CensoredForLog(messages[i]);
            }
            Console::Instance().XmlFailure(messages);
        }
        Console::Instance().XmlEndGroup();
    }
    if (mErrors != before && (mBatchMode == BatchMode::Abort || mBatchMode == BatchMode::On))
    {
        mExit = true;
    }
    return keepRunning && !mExit;
}

bool Script::ExecuteCommand(const std::string & line)
{
    std::string trimmed = line;
    size_t start = trimmed.find_first_not_of(" \t\r\n");
    if (start == std::string::npos || trimmed[start] == '#')
    {
        return true;
    }
    trimmed = trimmed.substr(start);

    std::vector<std::string> words = SplitCommandLine(trimmed);
    if (words.empty())
    {
        return true;
    }
    std::string command = ToLower(words[0]);
    std::vector<std::string> args(words.begin() + 1, words.end());

    /*
     * Upstream keeps the commands in a table and runs the single command an
     * abbreviation can only mean, so 'synch local remote' works. An
     * abbreviation of several commands is refused instead of guessing; 'x'
     * would be 'exit' or nothing at all, and 'get' versus 'g' is a typo
     * waiting to move files.
     */
    if (!IsKnownCommand(command))
    {
        std::string resolved;
        if (ResolveAbbreviation(CommandNames(), command, "command", resolved))
        {
            if (!resolved.empty())
            {
                command = resolved;
            }
        }
        else
        {
            return true;
        }
    }

    if (command == "exit" || command == "bye" || command == "quit" || command == "end")
    {
        if (!args.empty())
        {
            Console::Instance().Error(Texts::WrongArguments(command,
                Texts::Translate("The command takes no arguments.")));
            mErrors++;
            return true;
        }
        mExit = true;
        return false;
    }
    if (command == "help" || command == "?" || command == "man")
    {
        PrintHelp(args);
        return true;
    }
    if (command == "echo")
    {
        /* Print the message with its original spacing: the line is
         * re-split after the command word, which keeps quoted words
         * together and everything else apart. */
        std::string rest = trimmed.substr(words[0].size());
        while (!rest.empty() && (rest[0] == ' ' || rest[0] == '\t'))
        {
            rest.erase(0, 1);
        }
        Console::Instance().WriteLine(rest);
        return true;
    }
    if (command == "open")
    {
        OpenSite(args);
        return true;
    }
    if (command == "close")
    {
        CloseSite(args);
        return true;
    }
    if (command == "cd")
    {
        ChangeRemoteDirectory(args);
        return true;
    }
    if (command == "pwd")
    {
        PrintRemoteDirectory();
        return true;
    }
    if (command == "ls" || command == "dir")
    {
        ListRemote(args);
        return true;
    }
    if (command == "versions")
    {
        ListS3Versions(args);
        return true;
    }
    if (command == "lcd")
    {
        ChangeLocalDirectory(args);
        return true;
    }
    if (command == "lls")
    {
        ListLocal(args);
        return true;
    }
    if (command == "binary" || command == "ascii")
    {
        if (!args.empty())
        {
            Console::Instance().Error(Texts::WrongArguments(command,
                Texts::Translate("The command takes no arguments.")));
            mErrors++;
            return true;
        }
        std::vector<std::string> optionArgs;
        optionArgs.push_back("transfer");
        optionArgs.push_back(command);
        SetOption(optionArgs);
        return true;
    }
    if (command == "lpwd")
    {
        PrintLocalDirectory();
        return true;
    }
    if (command == "get" || command == "recv" || command == "mget")
    {
        GetFiles(args);
        return true;
    }
    if (command == "put" || command == "send" || command == "mput")
    {
        PutFiles(args);
        return true;
    }
    if (command == "synchronize" || command == "sync")
    {
        SynchronizeDirectories(args);
        return true;
    }
    if (command == "keepuptodate")
    {
        KeepUpToDate(args);
        return true;
    }
    if (command == "edit")
    {
        EditRemoteFile(args);
        return true;
    }
    if (command == "session")
    {
        SessionCommand(args);
        return true;
    }
    if (command == "sessions")
    {
        StoredSessionsCommand(args);
        return true;
    }
    if (command == "savesession")
    {
        SaveStoredSession(args);
        return true;
    }
    if (command == "savepreset")
    {
        SavePresetCommand(args);
        return true;
    }
    if (command == "rmspreset")
    {
        RemovePresetCommand(args);
        return true;
    }
    if (command == "presets")
    {
        ListPresetsCommand(args);
        return true;
    }
    if (command == "rmsession" || command == "delsession")
    {
        RemoveStoredSessionEntry(args);
        return true;
    }
    if (command == "rm" || command == "del")
    {
        RemoveRemote(args);
        return true;
    }
    if (command == "rmdir")
    {
        RemoveRemoteDirectory(args);
        return true;
    }
    if (command == "mkdir" || command == "md")
    {
        MakeRemoteDirectory(args);
        return true;
    }
    if (command == "mv" || command == "rename")
    {
        MoveRemote(args);
        return true;
    }
    if (command == "cp")
    {
        CopyRemote(args);
        return true;
    }
    if (command == "ln" || command == "symlink")
    {
        LinkRemote(args, command.c_str());
        return true;
    }
    if (command == "checksum")
    {
        ChecksumRemote(args);
        return true;
    }
    if (command == "lock")
    {
        LockRemote(args);
        return true;
    }
    if (command == "unlock")
    {
        UnlockRemote(args);
        return true;
    }
    if (command == "property")
    {
        DavPropertyCommand(args);
        return true;
    }
    if (command == "etag")
    {
        EtagCommand(args);
        return true;
    }
    if (command == "call")
    {
        CallRemote(args, "call");
        return true;
    }
    if (command == "!")
    {
        /* Upstream: '! <command>' is a synonym of 'call'. */
        CallRemote(args, "!");
        return true;
    }
    if (command == "copyid")
    {
        CopyPublicKey(args);
        return true;
    }
    if (command == "chmod")
    {
        ChangeRemotePermissions(args);
        return true;
    }
    if (command == "stat")
    {
        StatRemote(args);
        return true;
    }
    if (command == "attr")
    {
        AttrRemote(args);
        return true;
    }
    if (command == "option")
    {
        SetOption(args);
        return true;
    }
    if (command == "terminal")
    {
        OpenTerminal(args);
        return true;
    }
    if (command == "show")
    {
        Console::Instance().Error(Texts::WrongArguments(command,
            Texts::Translate(
                "The connection runs the SFTP subsystem, so remote shell "
                "commands are not available in this build.")));
        mErrors++;
        return true;
    }

    Console::Instance().Error(Texts::UnknownCommand(command));
    mErrors++;
    return true;
}

int Script::RunFile(const std::string & path)
{
    if (!mBatchConfigured)
    {
        mBatchMode = BatchMode::Abort;
        Console::Instance().SetBatchMode(true);
    }

    FILE * file = stdin;
    bool closeFile = false;
    if (path != "-")
    {
        file = fopen(path.c_str(), "rb");
        if (file == NULL)
        {
            Console::Instance().Error(Texts::Translate(
                "Cannot open the script file '{path}': {reason}",
                {{"path", path}, {"reason", LastSystemError()}}));
            return 1;
        }
        closeFile = true;
    }

    while (!mExit)
    {
        std::string line;
        bool sawInput = false;
        int c = EOF;
        while ((c = fgetc(file)) != EOF)
        {
            sawInput = true;
            if (c == '\n')
            {
                break;
            }
            if (c != '\r')
            {
                line += static_cast<char>(c);
            }
        }
        if (!sawInput && c == EOF)
        {
            break;
        }
        std::string expanded;
        if (ExpandParameters(line, expanded))
        {
            ExecuteLine(expanded);
        }
        else
        {
            /* A broken placeholder stops this line only; 'batch on' and
             * 'continue' still decide whether the run goes on. */
            if (mBatchMode == BatchMode::Abort || mBatchMode == BatchMode::On)
            {
                mExit = true;
            }
        }
        if (c == EOF)
        {
            break;
        }
    }
    if (ferror(file))
    {
        Console::Instance().Error(Texts::Translate(
            "Error while reading the script file '{path}'.", {{"path", path}}));
        mErrors++;
    }
    if (closeFile && fclose(file) != 0)
    {
        Console::Instance().Error(Texts::Translate(
            "Error while closing the script file '{path}'.", {{"path", path}}));
        mErrors++;
    }
    return mErrors != 0 ? 1 : 0;
}

int Script::RunCommand(const std::string & line, bool literal)
{
    if (!mBatchConfigured)
    {
        mBatchMode = BatchMode::Abort;
        Console::Instance().SetBatchMode(true);
    }

    /* '-command=' may carry several commands separated by ';'. Each is
     * expanded on its own, so a parameter value that holds a ';' cannot
     * start a command of its own. GUI-generated commands use -literal:
     * remote file names such as %TIMESTAMP%.txt are data, not templates. */
    std::vector<std::string> commands = SplitCommands(line);
    for (size_t i = 0; i < commands.size(); i++)
    {
        if (!commands[i].empty())
        {
            std::string expanded;
            if (literal || ExpandParameters(commands[i], expanded))
            {
                ExecuteLine(literal ? commands[i] : expanded);
            }
            else if (mBatchMode == BatchMode::Abort || mBatchMode == BatchMode::On)
            {
                mExit = true;
            }
        }
        if (mExit)
        {
            break;
        }
    }
    return mErrors != 0 ? 1 : 0;
}

int Script::RunInteractive(const std::string & initialUrl)
{
    if (!initialUrl.empty())
    {
        std::vector<std::string> args;
        args.push_back(initialUrl);
        OpenSite(args);
    }
    Console & console = Console::Instance();
    std::string line;
    while (!mExit)
    {
        if (!console.ReadLine("sftp> ", line))
        {
            break;
        }
        std::string expanded;
        if (ExpandParameters(line, expanded))
        {
            ExecuteLine(expanded);
        }
        /* A Ctrl-C that stopped 'keepuptodate' leaves the flag set, and the
         * engines that watch it would then abort the next command before it
         * transferred anything. The prompt is a fresh start. */
        ClearInterrupt();
    }
    return mErrors != 0 ? 1 : 0;
}

int Script::RunServer()
{
    /* The graphical client drives one of these per session: it keeps the
     * connection open between two operations instead of logging in again
     * for every listing. Errors do not end the server; the outcome of
     * every command is reported on a marker line. */
    mBatchMode = BatchMode::Continue;
    mBatchConfigured = true;
    mServerLoop = true;
    Console & console = Console::Instance();
    console.SetBatchMode(true);

    console.WriteLine("LSCP-SERVER 1 ready");

    std::string line;
    while (!mExit)
    {
        if (!console.ReadLine(std::string(), line))
        {
            break;
        }
        std::string trimmed = line;
        while (!trimmed.empty() &&
            (trimmed[trimmed.size() - 1] == '\r' || trimmed[trimmed.size() - 1] == '\n'))
        {
            trimmed.erase(trimmed.size() - 1);
        }
        if (trimmed.find_first_not_of(" \t") == std::string::npos ||
            trimmed[trimmed.find_first_not_of(" \t")] == '#')
        {
            continue;
        }
        const bool keepRunning = ExecuteLine(trimmed);
        console.WriteLine(std::string("LSCP-RESULT ") + (mLastCommandFailed ? "1" : "0"));
        if (!keepRunning)
        {
            break;
        }
        /* As at the interactive prompt: an interrupt that stopped the command
         * just reported must not stop the next one before it starts. */
        ClearInterrupt();
    }
    return mErrors != 0 ? 1 : 0;
}

} // namespace linscp
