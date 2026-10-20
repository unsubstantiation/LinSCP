#ifndef LINSCP_PROTOCOLCLIENT_H
#define LINSCP_PROTOCOLCLIENT_H

#include <string>
#include <vector>
#include "Session.h"
#include "SftpClient.h"

namespace linscp {

/*
 * The curl exit codes that say the endpoint itself is unusable (it
 * could not be reached, the transport failed, it refused us at the
 * protocol level). Anything else is the server answering, which
 * 'open' must not second-guess. Shared with S3Client.cpp, whose
 * requests are signed but whose transport is the same curl.
 */
bool IsCurlEndpointUnreachable(int code);

/*
 * The pieces of the WebDAV lock and dead-property extensions that can be
 * checked without a server: the lock token inside a LOCK response body,
 * the rules a property name has to follow, and the request bodies and
 * replies for one property. Exposed so the unit suite can pin them.
 */
bool DavLockTokenFromXml(const std::string & xml, std::string & token);
/* The lock token this session holds for a path, or an empty string. */
std::string DavTokenFor(const SessionOptions & options,
    const std::string & remotePath);
/* An entity tag as an If header carries it: quoted, 'W/' kept in front of
 * the quotes, and '*' left standing for any tag. */
std::string DavEntityTag(const std::string & value);
/* The If header a WebDAV write of a path carries: the lock token and the
 * ETag precondition the session recorded for it, as the one condition list
 * RFC 4918 reads. Empty when the session states nothing about the path. */
std::string DavIfHeader(const SessionOptions & options,
    const std::string & remotePath);
bool DavValidPropertyName(const std::string & name, std::string & error);
std::string DavPropertyPropfindBody(const std::string & name);
std::string DavPropertyUpdateBody(const std::string & name,
    const std::string & value);
bool DavPropertyValueFromXml(const std::string & xml, const std::string & name,
    std::string & value, bool & found);

/* Runs curl with its progress meter enabled and translates the meter into
 * byte callbacks. This is shared by the generic protocol client and S3;
 * the caller supplies all curl arguments, so credentials and URLs remain
 * in the same child process as ordinary transfers. */
int RunCurlCaptureWithProgress(const std::vector<std::string> & args,
    std::string & out, std::string & error, LscpProgressFn progress,
    void * progressCtx, bool upload);

/* SOCKS5h to the jump listener so TLS SNI, the Host header and S3
 * signing keep the original destination name. Empty when the session
 * has no destination tunnel. */
void AddCurlTunnelArgs(const SessionOptions & options,
    std::vector<std::string> & args);

class ProtocolClient
{
public:
    static bool IsMultiProtocol(const std::string & protocol);
    /* True for the two spellings a WebDAV session is opened with. 'http'
     * and 'https' are not DAV here: a plain HTTP session has no PROPFIND
     * server behind it, so the DAV code paths must not claim it. Asked from
     * Script.cpp by the commands that only a WebDAV server can answer. */
    static bool IsDavProtocol(const std::string & protocol);

    static bool List(const SessionOptions & options, const std::string & remotePath,
        LscpNames * names, std::string & error);

    static int Stat(const SessionOptions & options, const std::string & remotePath,
        LscpAttrs * attrs, std::string & error);

    /* speedKBytesPerSecond limits the transfer rate (0 is unlimited); it
     * corresponds to the '-speed=' switch of get and put. */
    static int Get(const SessionOptions & options, const std::string & remotePath,
        const std::string & localPath, unsigned long long resumeOffset,
        bool preserveTime, unsigned long long * size, LscpProgressFn progress,
        void * progressCtx, std::string & error, unsigned speedKBytesPerSecond = 0);

    static int Put(const SessionOptions & options, const std::string & localPath,
        const std::string & remotePath, int permissions, unsigned long long resumeOffset,
        bool preserveTime, unsigned long long * size, LscpProgressFn progress,
        void * progressCtx, std::string & error, unsigned speedKBytesPerSecond = 0);

    /*
     * WebDAV locks and dead properties. Upstream's WebDAV backend sends no
     * LOCK, UNLOCK or PROPPATCH at all, so these are LinSCP extensions; a
     * server that does not implement one answers 405 and the command says
     * so rather than pretending the write was protected. DavLock returns
     * the server's token, DavSetProperty moves a property in the
     * 'urn:linscp:properties' namespace, and DavGetProperty reports
     * 'found' false when the server answered with a 404 propstat.
     */
    static bool DavLock(const SessionOptions & options, const std::string & remotePath,
        int timeoutSeconds, std::string & token, std::string & error);
    static bool DavUnlock(const SessionOptions & options, const std::string & remotePath,
        const std::string & token, std::string & error);
    static bool DavSetProperty(const SessionOptions & options, const std::string & remotePath,
        const std::string & name, const std::string & value, std::string & error);
    static bool DavGetProperty(const SessionOptions & options, const std::string & remotePath,
        const std::string & name, std::string & value, bool & found, std::string & error);

    /*
     * WebDAV ETag preconditions: retrieve the current ETag of a resource
     * and apply If-Match/If-None-Match conditional write headers.
     * An empty 'etag' with true returned is an answer, not a failure, and
     * 'pathMissing' says which one it was: the path is not there, or the
     * server answered PROPFIND without a getetag property. Returns false
     * only when the server did not answer at all.
     */
    static bool DavGetEtag(const SessionOptions & options,
        const std::string & remotePath, std::string & etag,
        bool & pathMissing, std::string & error);

    /*
     * Ask the endpoint whether it is there at all, by listing a directory.
     * The curl-backed protocols have no connection of their own, so without
     * this an 'open' of a misspelled host or a dead port would report
     * success and every command afterwards would fail on its own. Only a
     * failure to reach or authenticate at the endpoint is reported as false:
     * a directory the server refuses to list counts as an answer.
     */
    static bool CheckEndpoint(const SessionOptions & options,
        const std::string & remotePath, std::string & error);

    static int Remove(const SessionOptions & options, const std::string & remotePath,
        std::string & error);

    static int RemoveDir(const SessionOptions & options, const std::string & remotePath,
        std::string & error);

    static int MakeDir(const SessionOptions & options, const std::string & remotePath,
        std::string & error);

    /* Server-side file copy where the protocol provides it. Returns 1 when
     * no copy operation is available so the caller can stream through the
     * client, 0 on success, and -1 on a real server/transport failure. */
    static int Copy(const SessionOptions & options, const std::string & fromPath,
        const std::string & toPath, std::string & error);

    static int Move(const SessionOptions & options, const std::string & fromPath,
        const std::string & toPath, std::string & error);

    static int SetPermissions(const SessionOptions & options,
        const std::string & remotePath, int permissions, std::string & error);

    static void FreeNames(LscpNames * names);
};

} // namespace linscp

#endif /* LINSCP_PROTOCOLCLIENT_H */
