/*
 * SftpClient: the SFTP protocol operations of the POSIX front end.
 *
 * The SFTP v3 wire protocol is spoken by SftpClient.cpp directly -
 * including the OpenSSH copy-data and check-file-name extensions, for
 * which libssh's own SFTP client has no API - over the libssh subsystem
 * channel owned by Session. The front end gets this plain C API, with no
 * libssh types in it; the byte transport is Session::SendData and
 * Session::ReceiveData on the current session.
 */

#ifndef LINSCP_SFTPCLIENT_H
#define LINSCP_SFTPCLIENT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LSCP_ATTR_SIZE        0x00000001u
#define LSCP_ATTR_UIDGID      0x00000002u
#define LSCP_ATTR_PERMISSIONS 0x00000004u
#define LSCP_ATTR_ACMODTIME   0x00000008u

enum
{
    LSCP_SFTP_STAT_ERROR = -1,
    LSCP_SFTP_STAT_EXISTS = 0,
    LSCP_SFTP_STAT_MISSING = 1
};

typedef struct LscpAttrs
{
    unsigned long flags;
    unsigned long long size;
    unsigned long uid;
    unsigned long gid;
    unsigned long permissions;
    unsigned long atime;
    unsigned long mtime;
} LscpAttrs;

typedef struct LscpName
{
    char * filename;
    char * longname;
    LscpAttrs attrs;
} LscpName;

typedef struct LscpNames
{
    int count;
    LscpName * names;
} LscpNames;

typedef void (*LscpProgressFn)(unsigned long long transferred,
    unsigned long long total, void * ctx);

/* Integer operations return 0 on success and -1 on failure, except stat,
 * which returns the values above to distinguish a missing path. Details are
 * available from lscp_sftp_error(). */

int lscp_sftp_init(void);
/* Release any outstanding request bookkeeping when a session is torn down. */
void lscp_sftp_cleanup(void);
const char * lscp_sftp_error(void);

/* Returns a newly allocated absolute path, or NULL. */
char * lscp_sftp_realpath(const char * path);

/* Returns a newly allocated listing, or NULL. Free with lscp_sftp_free_names. */
LscpNames * lscp_sftp_list_dir(const char * path);
void lscp_sftp_free_names(LscpNames * names);

/* Returns LSCP_SFTP_STAT_EXISTS, _MISSING or _ERROR. */
int lscp_sftp_stat(const char * path, LscpAttrs * attrs);
int lscp_sftp_mkdir(const char * path, int permissions);
int lscp_sftp_rmdir(const char * path);
int lscp_sftp_remove(const char * path);
int lscp_sftp_rename(const char * from, const char * to);
/* permissions < 0 leaves the permissions unchanged */
int lscp_sftp_set_permissions(const char * path, int permissions);
/* Sets the access and modification times of a remote file. */
int lscp_sftp_set_times(const char * path, unsigned long atime,
    unsigned long mtime);

/* Creates a symbolic link at linkPath pointing at target (SSH_FXP_SYMLINK
 * of SFTP v3). */
int lscp_sftp_symlink(const char * target, const char * linkPath);

/* Server-side copy through the copy-data extension (OpenSSH and other
 * v3 servers). Returns 0 on success, -1 with lscp_sftp_error() set
 * when the server cannot copy server-side (the caller can then copy
 * through a stream), and -2 when the extension is not supported. */
int lscp_sftp_copy(const char * from, const char * to);

/* Server-side checksum through the check-file-name extension. On
 * success 'algorithm' holds what the server used and 'hex' the digest.
 * Returns 0, -1 (failed) or -2 (extension not supported). The buffer
 * must hold at least 2*LSCP_MAX_CHECKSUM_BYTES+1 bytes of hex. */
#define LSCP_MAX_CHECKSUM_BYTES 64
int lscp_sftp_checksum(const char * algorithm, const char * path,
    char * usedAlgorithm, size_t usedAlgorithmSize,
    char * hex, size_t hexSize);

/* size may be NULL. On success it holds the number of bytes transferred. */
int lscp_sftp_get(const char * remotePath, const char * localPath,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx);
int lscp_sftp_get_resume(const char * remotePath, const char * localPath,
    unsigned long long resumeOffset, unsigned long long * size,
    LscpProgressFn progress, void * progressCtx);

int lscp_sftp_put(const char * localPath, const char * remotePath, int permissions,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx);
int lscp_sftp_put_resume(const char * localPath, const char * remotePath, int permissions,
    unsigned long long resumeOffset, unsigned long long * size,
    LscpProgressFn progress, void * progressCtx);

/* Appends the source file to the destination instead of replacing it. A
 * missing destination is created. These two have no counterpart on the curl
 * backends, which cannot position a write in a remote file. */
int lscp_sftp_get_append(const char * remotePath, const char * localPath,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx);
int lscp_sftp_put_append(const char * localPath, const char * remotePath,
    int permissions, unsigned long long * size, LscpProgressFn progress,
    void * progressCtx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LINSCP_SFTPCLIENT_H */
