#ifndef LINSCP_S3CLIENT_H
#define LINSCP_S3CLIENT_H

#include <string>
#include <vector>

#include "Session.h"
#include "SftpClient.h"

namespace linscp {

struct S3ObjectVersion
{
    std::string key;
    std::string versionId;
    bool isLatest;
    bool isDeleteMarker;
    unsigned long long size;
    unsigned long mtime;

    S3ObjectVersion() : isLatest(false), isDeleteMarker(false), size(0),
        mtime(0) {}
};

/*
 * Amazon S3 over HTTPS with AWS Signature Version 4: a real bucket and
 * object filesystem on top of the flat object store - ListObjectsV2
 * with a delimiter for directories, zero-byte "key/" markers for
 * mkdir, copy-plus-delete for rename, HEAD for stat.
 *
 * Credentials are the site's user name (access key ID) and password
 * (secret access key), given as s3://ACCESSKEY:SECRET@host/bucket/ or
 * through -username=/-password=. The region comes from AWS_REGION or
 * AWS_DEFAULT_REGION, else from an s3.<region>.amazonaws.com host,
 * else us-east-1. Every request carries x-amz-content-sha256 (the hash
 * of an empty body, or UNSIGNED-PAYLOAD for uploads) because S3
 * requires that header to be signed. Small objects use PutObject; files
 * larger than 16 MiB use the S3 multipart API with an 8 MiB minimum part
 * size (scaled as needed to stay under 10,000 parts). A private local
 * sidecar stores the upload ID, source size/mtime, part size and completed
 * ETags so a matching retry skips uploaded parts; stale state is aborted
 * rather than reused. On a handled failure the client attempts to abort the
 * multipart upload.
 *
 * The signing itself lives in S3SigV4.cpp (pure strings, unit-tested
 * against AWS's published examples); this file is the HTTP side: one
 * curl process per request, the response code parsed from
 * --write-out, the S3 error document read for its Code/Message when
 * something fails.
 */
class S3Client
{
public:
    static bool List(const SessionOptions & options,
        const std::string & remotePath, LscpNames * names,
        std::string & error);

    /* Version-aware operations. ListVersions accepts an object path for an
     * exact-key listing, or a trailing-slash/bucket-root prefix for all
     * versions below it. */
    static bool ListVersions(const SessionOptions & options,
        const std::string & remotePath, std::vector<S3ObjectVersion> & versions,
        std::string & error);
    static int StatVersion(const SessionOptions & options,
        const std::string & remotePath, const std::string & versionId,
        LscpAttrs * attrs, std::string & error);
    static int RemoveVersion(const SessionOptions & options,
        const std::string & remotePath, const std::string & versionId,
        std::string & error);

    static int Stat(const SessionOptions & options,
        const std::string & remotePath, LscpAttrs * attrs,
        std::string & error);

    static int Get(const SessionOptions & options,
        const std::string & remotePath, const std::string & localPath,
        unsigned long long resumeOffset, bool preserveTime,
        unsigned long long * size, LscpProgressFn progress,
        void * progressCtx, std::string & error,
        unsigned speedKBytesPerSecond = 0,
        const std::string & versionId = std::string());

    static int Put(const SessionOptions & options,
        const std::string & localPath, const std::string & remotePath,
        int permissions, unsigned long long resumeOffset,
        bool preserveTime, unsigned long long * size,
        LscpProgressFn progress, void * progressCtx, std::string & error,
        unsigned speedKBytesPerSecond = 0);

    static bool CheckEndpoint(const SessionOptions & options,
        const std::string & remotePath, std::string & error);

    static int Remove(const SessionOptions & options,
        const std::string & remotePath, std::string & error);

    static int RemoveDir(const SessionOptions & options,
        const std::string & remotePath, std::string & error);

    static int MakeDir(const SessionOptions & options,
        const std::string & remotePath, std::string & error);

    /* Returns 0 when a server-side CopyObject succeeds. */
    static int Copy(const SessionOptions & options,
        const std::string & fromPath, const std::string & toPath,
        std::string & error);

    static int Move(const SessionOptions & options,
        const std::string & fromPath, const std::string & toPath,
        std::string & error);
};

} // namespace linscp

#endif /* LINSCP_S3CLIENT_H */
