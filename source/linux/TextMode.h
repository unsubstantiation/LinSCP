/*
 * TextMode: LinSCP's transfer modes (binary, ASCII and automatic).
 *
 * In ASCII mode a text file is converted between the line endings of
 * the two sides: CRLF on the remote side becomes LF on a POSIX local
 * side when downloading, and LF becomes CRLF when uploading.
 * 'Automatic' applies that conversion only to files whose name matches
 * the ASCII file mask below, like LinSCP's default configuration.
 *
 * The conversion happens around a binary transfer: a download is
 * converted in place afterwards, an upload is converted into a
 * temporary copy first so that the local file is never modified.
 */

#ifndef LINSCP_TEXTMODE_H
#define LINSCP_TEXTMODE_H

#include <string>

namespace linscp {

/* Which files 'automatic' mode converts. This is LinSCP's default list
 * of text file extensions. */
extern const char * const kAsciiFileMask;

enum class TransferMode
{
    Binary,
    Ascii,
    Automatic
};

const char * TransferModeName(TransferMode mode);
/* Reads 'binary', 'ascii' or 'automatic' into 'mode'. */
bool ParseTransferMode(const std::string & text, TransferMode & mode);

/* True when 'name' matches the ASCII file mask. */
bool IsAsciiFileName(const std::string & name);

/* True when a file of this name must be converted in 'mode'. */
bool WantsAsciiConversion(TransferMode mode, const std::string & name);

/* Rewrites 'path' in place, turning CRLF and lone CR into LF. 'bytes'
 * receives the new size. */
bool ConvertToUnixLineEndings(const std::string & path,
    unsigned long long & bytes, std::string & error);

/* Writes a copy of 'source' with LF turned into CRLF to a temporary
 * file in the same directory; 'tempPath' receives its name. The caller
 * removes it. */
bool MakeCRLFUploadCopy(const std::string & source, std::string & tempPath,
    std::string & error);

} // namespace linscp

#endif /* LINSCP_TEXTMODE_H */
