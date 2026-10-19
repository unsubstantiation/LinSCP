/*
 * ScpClient: the native SCP engine.
 *
 * SCP is not a filesystem protocol: it is a login shell plus the rcp
 * transfer protocol that runs on it, and upstream drives both. Listings,
 * stat and the metadata operations are shell commands; the bytes of a
 * transfer go through 'scp -f' and 'scp -t' on an SSH channel whose wire
 * protocol the client speaks itself. This engine does the same over
 * libssh, so an scp:// session no longer needs a curl built
 * with libssh2, and its host key is verified by the code that verifies an
 * sftp:// one instead of being handed to curl's fingerprint options.
 *
 * Every operation is one SSH connection of its own: the command runs in an
 * 'exec' channel, its standard output is read, the exit status the server
 * reports decides success, and the connection closes again. That is what
 * the curl backend does per invocation as well, and it keeps the engine
 * stateless between commands - there is no shell prompt to recognise and no
 * working directory to remember, because every path sent to the server is
 * absolute.
 *
 * A path is an argument on a remote command line, so it is single-quoted
 * for a POSIX shell, and a path holding a control character is refused
 * instead of being sent: a newline in a name cannot be told apart from the
 * end of an 'ls -l' line, and a name that cannot be listed safely is not a
 * name to transfer either.
 *
 * What this engine cannot do is continue a partial transfer: the rcp
 * protocol has no offset, so a download or an upload always starts at byte
 * zero. The '.filepart' staging still applies (an interrupted transfer is
 * not left under the final name, and the engine can rename remotely), but a
 * staging file that is already there is discarded and the transfer restarts
 * rather than being spliced onto bytes nobody can vouch for.
 */

#ifndef LINSCP_SCPCLIENT_H
#define LINSCP_SCPCLIENT_H

#include <string>
#include <vector>

#include "ListingParse.h"
#include "SftpClient.h"
#include "Session.h"

namespace linscp {

/* Set in the 'codeOut' of List when the failure was the connection itself -
 * the host could not be reached, the host key did not match or the
 * credentials were refused - rather than the server answering a command.
 * 'open' uses it to tell an unusable endpoint from a directory the server
 * will not list, exactly as the FTP engine's kFtpTransportFailure does. */
const int kScpTransportFailure = -1;

/*
 * The parts of the engine that need no connection, exposed so the unit
 * suite can pin them: quoting a path for a remote shell, the paths the
 * engine refuses to send, one 'ls -l' line as an entry, and the header
 * lines of the rcp protocol in both directions.
 */

/* Quotes one word for a POSIX shell: everything goes inside single quotes,
 * and a quote inside becomes the '\'' sequence. */
std::string ScpShellQuote(const std::string & text);

/* Whether 'path' can be sent to a remote shell and listed again: no empty
 * path and no control character in it. 'error' says why not. */
bool ScpValidRemotePath(const std::string & path, std::string & error);

/* The three date columns GNU 'ls --full-time' prints ('2026-10-16',
 * '05:33:07.123456789', '+0000') as seconds since the epoch, which is what
 * makes a timestamp from a shell listing exact instead of a minute - or a
 * year, for a file older than six months. Returns 0 for columns that are not
 * that shape, so a plain listing stays a plain listing. */
unsigned long ScpParseFullTime(const std::string & dateText,
    const std::string & timeText, const std::string & offsetText);

/* One line of an 'ls -l -a' listing as an entry. Returns false for the
 * 'total' summary, for '.' and '..', and for a line that is not a long
 * listing at all - which is also how output a shell printed before the
 * command ran is kept out of the listing. A symbolic link keeps its own
 * name: the ' -> target' half of the line is not part of it. */
bool ScpParseListingLine(const std::string & line, ListingEntry & entry);

/* The header lines of the rcp protocol. 'kind' is the leading byte: 'C' a
 * file, 'D' a directory, 'E' the end of one, 'T' a timestamp pair, 1 an
 * error and 2 a fatal one. Returns false for a line that is none of them. */
bool ScpParseHeaderLine(const std::string & line, char & kind,
    unsigned int & mode, unsigned long long & size, std::string & name,
    unsigned long & mtime, unsigned long & atime);

/* The lines the sending side writes: 'C0644 512 name', 'D0755 0 name' and
 * 'T<mtime> 0 <atime> 0'. */
std::string ScpFileHeaderLine(unsigned int mode, unsigned long long size,
    const std::string & name);
std::string ScpDirectoryHeaderLine(unsigned int mode, const std::string & name);
std::string ScpTimeHeaderLine(unsigned long mtime, unsigned long atime);

/* 'touch -t' needs the server's own reading of a timestamp, so the engine
 * asks for UTC and gives the POSIX form: 202610160533.07. */
std::string ScpTouchStamp(unsigned long secondsSinceEpoch);

/* True when the text a command printed on its error output says the path
 * is not there, which is what makes 'stat' answer "missing" instead of
 * "error". */
bool ScpSaysMissing(const std::string & text);

class ScpClient
{
public:
    /* True when this session belongs to the native engine: scp:// and the
     * ssh:// spelling of the same protocol. */
    static bool Handles(const SessionOptions & options);

    /* 'ls -l -a' through the shared long-listing parser. */
    static bool List(const SessionOptions & options, const std::string & remotePath,
        std::vector<ListingEntry> & entries, std::string & error,
        int * codeOut = NULL);

    /* 'ls -l -d'. Returns the LSCP_SFTP_STAT_* codes the rest of the
     * client uses, so a missing path stays distinguishable from a server
     * that refused to answer. */
    static int Stat(const SessionOptions & options, const std::string & remotePath,
        LscpAttrs * attrs, std::string & error);

    static int Remove(const SessionOptions & options, const std::string & remotePath,
        std::string & error);
    static int RemoveDir(const SessionOptions & options, const std::string & remotePath,
        std::string & error);
    static int MakeDir(const SessionOptions & options, const std::string & remotePath,
        std::string & error);
    static int Move(const SessionOptions & options, const std::string & fromPath,
        const std::string & toPath, std::string & error);
    /* Server-side copy through the shell's own 'cp'. Returns 1 when the
     * server has no 'cp' to run, so the caller streams through the client
     * instead, 0 on success and -1 on a real failure. */
    static int Copy(const SessionOptions & options, const std::string & fromPath,
        const std::string & toPath, std::string & error);
    static int SetPermissions(const SessionOptions & options,
        const std::string & remotePath, int permissions, std::string & error);

    /* The metadata the shell can set that 'ls -l' can read back: the
     * modification time (through 'touch', which sets the access time to the
     * same value) and a symbolic link. */
    static bool SetTimes(const SessionOptions & options,
        const std::string & remotePath, unsigned long atime,
        unsigned long mtime, std::string & error);
    static bool MakeSymlink(const SessionOptions & options,
        const std::string & target, const std::string & linkPath,
        std::string & error);

    /* The absolute path a relative or symlinked one names, through
     * 'cd <path> && pwd'. 'cd' with no argument and the initial directory
     * of a site are resolved with it. */
    static bool ResolvePath(const SessionOptions & options,
        const std::string & remotePath, std::string & resolved,
        std::string & error);

    /* The directory a login starts in ('home') and the one a site's initial
     * path names, answered by one command - 'pwd' and then
     * 'cd <path> && pwd' - so that opening a session costs one connection
     * rather than two. A path the server will not change into fails here,
     * which is where 'open' can still say why. */
    static bool ResolveHomeAndInitial(const SessionOptions & options,
        const std::string & initialPath, std::string & home,
        std::string & resolved, std::string & error);

    /* Whether the endpoint is there at all: one command that only has to
     * connect, authenticate and run. A host key that does not match, a
     * refused login or an unreachable port fails here, where 'open' can say
     * so; a directory the server will not change into is the command's
     * business and counts as an answer. */
    static bool CheckEndpoint(const SessionOptions & options,
        const std::string & remotePath, std::string & error);

    /* 'scp -f' / 'scp -t': one file each way, with the progress callback
     * the SFTP transport uses and the '-speed=' limit applied by waiting
     * between chunks. A nonzero resumeOffset is refused: the protocol has
     * no offset to continue from. */
    static int Get(const SessionOptions & options, const std::string & remotePath,
        const std::string & localPath, unsigned long long resumeOffset,
        bool preserveTime, unsigned long long * size, LscpProgressFn progress,
        void * progressCtx, std::string & error,
        unsigned speedKBytesPerSecond = 0);
    static int Put(const SessionOptions & options, const std::string & localPath,
        const std::string & remotePath, int permissions,
        unsigned long long resumeOffset, bool preserveTime,
        unsigned long long * size, LscpProgressFn progress, void * progressCtx,
        std::string & error, unsigned speedKBytesPerSecond = 0);
};

} // namespace linscp

#endif /* LINSCP_SCPCLIENT_H */
