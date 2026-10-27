/*
 * Editor: remote file editing.
 *
 * 'edit' downloads a remote file into a private temporary directory,
 * starts an editor on it and uploads the file back when the editor
 * exits, which is how LinSCP's internal editor works from the console.
 * The file access is an interface so that every protocol backend can be
 * edited with the same code, and so the workflow can be tested without
 * a server.
 *
 * The graphical client uses the same idea with its own editor pane:
 * download, edit, upload. Its 'save' endpoint checks the modification
 * time it read when the file was opened, so a file that changed on the
 * server in the meantime is not silently overwritten.
 */

#ifndef LINSCP_EDITOR_H
#define LINSCP_EDITOR_H

#include <string>
#include <vector>

#include "SftpClient.h"

namespace linscp {

class Console;

/* The remote side of an edit session, implemented by Script for the
 * open connection. The integer results are 0 on success and -1 on
 * failure, with the reason in 'error'; Stat returns the values below. */
class RemoteFileAccess
{
public:
    virtual ~RemoteFileAccess() {}
    virtual int Stat(const std::string & path, LscpAttrs & attrs,
        std::string & error) = 0;
    virtual int Download(const std::string & remote, const std::string & local,
        bool preserveTime, std::string & error) = 0;
    virtual int Upload(const std::string & local, const std::string & remote,
        bool preserveTime, std::string & error) = 0;
};

struct EditOptions
{
    /* Editor command line (for example "vim" or "code --wait"). Empty:
     * $LINSCP_EDITOR, $VISUAL, $EDITOR, or a common editor. */
    std::string editor;
    /* Keep the temporary file after a successful upload, for
     * inspection. It is always kept when the upload fails. */
    bool keepTempFile;
    /* Largest file that is opened without an explicit -force. */
    unsigned long long maxSize;
    /* Edit a file that contains binary data anyway. */
    bool allowBinary;
    /* Ignore the size limit and the binary check. */
    bool force;
    /* Line-ending / BOM policy on upload: "preserve" (default), "lf",
     * or "crlf". */
    std::string eol;
    /* Monitor the local working copy for subsequent saves after the
     * editor command returns. */
    bool monitor;
    unsigned monitorPasses;
    unsigned monitorIntervalMs;

    EditOptions() : keepTempFile(false), maxSize(kDefaultMaxSize),
        allowBinary(false), force(false), eol("preserve"),
        monitor(false), monitorPasses(1), monitorIntervalMs(100) {}

    static const unsigned long long kDefaultMaxSize = 64ULL * 1024 * 1024;
};

/* True when 'data' looks like text rather than binary: no NUL byte in
 * the first 'length' bytes. */
bool LooksLikeText(const char * data, size_t length);

/* Normalizes line endings ("preserve", "lf", "crlf") and preserves a
 * leading UTF-8 BOM from 'originalBytes' when 'preserve' is active. */
std::string NormalizeEditedText(const std::string & originalBytes,
    const std::string & editedBytes, const std::string & eolPolicy);

/*
 * Non-UTF-8 encoding support: an explicit contract for legacy encodings
 * (ISO-8859-1, Windows-1252, EUC-JP, Shift-JIS, etc.) through iconv.
 * The browser editor still requires UTF-8, but the CLI can convert
 * files on the fly before sending them to the editor and after saving.
 */

/* True when 'data' starts with a UTF-8 BOM (EF BB BF). */
bool HasUtf8Bom(const std::string & data);

/* True when 'data' is valid UTF-8 (may contain a BOM). */
bool IsValidUtf8(const std::string & data);

/* Converts 'data' from 'fromEncoding' to UTF-8 via iconv. Returns the
 * converted bytes, or an empty string with 'error' set on failure.
 * Supported when the platform provides iconv (glibc, musl). */
std::string ConvertToUtf8(const std::string & data,
    const std::string & fromEncoding, std::string & error);

/* Converts 'data' from UTF-8 to 'toEncoding' via iconv. Returns the
 * converted bytes, or an empty string with 'error' set on failure. */
std::string ConvertFromUtf8(const std::string & data,
    const std::string & toEncoding, std::string & error);

/* The command line of the editor to run: the configured one, or the
 * first of the environment variables and installed editors. Empty with
 * 'error' set when none was found; an unknown configured program is an
 * error rather than a surprise. */
std::vector<std::string> ResolveEditorCommand(const std::string & configured,
    std::string & error);

/* Full path of the temporary copy of 'remotePath', inside the private
 * editor directory. The directory is created (0700 on POSIX). */
bool PrepareEditorTempFile(const std::string & remotePath, std::string & path,
    std::string & error);

class RemoteEditor
{
public:
    RemoteEditor(RemoteFileAccess & access, Console * console) :
        mAccess(access), mConsole(console) {}

    /* Downloads 'remotePath', runs the editor and uploads the result
     * when it changed. Returns false with 'error' set on failure; a
     * user's decision not to upload is not a failure. */
    bool Edit(const std::string & remotePath, const EditOptions & options,
        bool confirmUpload, std::string & error);

private:
    RemoteEditor(const RemoteEditor &);
    RemoteEditor & operator=(const RemoteEditor &);

    RemoteFileAccess & mAccess;
    Console * mConsole;    /* may be NULL: no status messages */
};

} // namespace linscp

#endif /* LINSCP_EDITOR_H */
