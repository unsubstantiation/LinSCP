/*
 * FtpClient: the native FTP engine.
 *
 * Plain FTP (no TLS) is served from here rather than from curl, because
 * the things that make FTP usable are protocol level and curl cannot
 * express them: MLSD/MLST (structured facts instead of a text LIST that
 * servers format differently), the active/passive policy, and the
 * per-command honesty of talking FTP on its own control connection.
 * Upstream's session setting names drive it: FtpPasvMode, FtpForcePasvIp,
 * FtpUseMlsd and FtpAccount.
 *
 * This is the directory and metadata half: listing, stat, create, remove,
 * rename and SITE CHMOD. Transfers still go through curl, which is the
 * same engine the other non-SFTP protocols use for their bytes, and
 * FTPS (implicit or explicit TLS) stays on curl as well: a TLS client
 * would need a TLS library this build does not link.
 *
 * Every call opens its own control connection and closes it again, which
 * is what the curl backend does per invocation as well. The engine is
 * therefore stateless between commands and reports the server's answer
 * (code and text) instead of hiding it.
 */

#ifndef LINSCP_FTPCLIENT_H
#define LINSCP_FTPCLIENT_H

#include <string>
#include <vector>

#include "ListingParse.h"
#include "SftpClient.h"
#include "Session.h"

namespace linscp {

/* Set in the 'codeOut' of List when the failure was at the transport
 * level - the host could not be reached, the connection broke, or the
 * credentials were refused - rather than the server answering a command.
 * 'open' uses it to tell an unusable endpoint from a directory the
 * server will not list. */
const int kFtpTransportFailure = -1;

/*
 * One decimal number out of a PASV/EPSV server reply, range-checked.
 * Exported for the unit suite; the engine uses it for every number a
 * reply carries, so a hostile or confused server cannot steer the data
 * connection with an out-of-range port or address octet.
 */
bool ParseFtpReplyNumber(const std::string & text, int low, int high,
    int & value);

class FtpClient
{
public:
    /* True when this session belongs to the native engine: plain FTP,
     * with no TLS mode set by the scheme or by 'Ftps='. */
    static bool Handles(const SessionOptions & options);

    /* MLSD when the server offers it and FtpUseMlsd allows it, LIST
     * otherwise, with the 'ls -l' parser shared with the curl backend. */
    static bool List(const SessionOptions & options, const std::string & remotePath,
        std::vector<ListingEntry> & entries, std::string & error, int * codeOut = NULL);

    /* MLST first, then SIZE/MDTM, then the parent listing. Returns the
     * LSCP_SFTP_STAT_* codes the rest of the client uses. */
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
    static int SetPermissions(const SessionOptions & options,
        const std::string & remotePath, int permissions, std::string & error);
};

} // namespace linscp

#endif /* LINSCP_FTPCLIENT_H */
