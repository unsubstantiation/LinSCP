/*
 * PathUtil: path handling shared by the front end.
 *
 * Remote (server side) paths are always POSIX: '/' separated, always
 * absolute once resolved against the current remote directory. Local
 * paths are POSIX too, since this client runs on Linux; the two families
 * are still kept in separate helpers, because a local path is resolved
 * against the local working directory and a remote one against the
 * session's.
 */

#ifndef LINSCP_PATHUTIL_H
#define LINSCP_PATHUTIL_H

#include <cstdint>
#include <string>
#include <vector>

namespace linscp {

/* Splits a script/command line into words. Handles single quotes, double
 * quotes and backslash escapes; the quotes themselves are not kept.
 *
 * The rules are the ones a POSIX shell uses, because the names on this
 * platform are POSIX names: a single-quoted word is literal, a
 * double-quoted word keeps its spaces, and a backslash escapes the
 * character behind it outside quotes. Inside double quotes a backslash
 * is literal unless it stands in front of a double quote or of another
 * backslash, so a Windows path keeps its separators there. */
std::vector<std::string> SplitCommandLine(const std::string & line);
/* Splits a command line holding several commands separated by ';' into the
 * individual commands. ';' inside quotes is kept. */
std::vector<std::string> SplitCommands(const std::string & text);

/* Remote paths. */
bool IsRemoteAbsolutePath(const std::string & path);
std::string RemoteDirName(const std::string & path);
std::string RemoteFileName(const std::string & path);
/* Joins a directory and a name, adding exactly one '/'. */
std::string JoinRemotePath(const std::string & dir, const std::string & name);
/* Resolves '.'/'..' components and relative paths against cwd. */
std::string ResolveRemotePath(const std::string & cwd, const std::string & path);

/* Leading and trailing whitespace removed; false when nothing is left. */
bool TrimString(const std::string & text, std::string & result);

/* Local paths. */
std::string ExpandTilde(const std::string & path);
/* True for a path that starts at the root ('/...'). */
bool IsLocalAbsolutePath(const std::string & path);
std::string LocalDirName(const std::string & path);
std::string LocalFileName(const std::string & path);
std::string JoinLocalPath(const std::string & dir, const std::string & name);
std::string ResolveLocalPath(const std::string & cwd, const std::string & path);
/* True if the path contains the wildcards we support in file masks. */
bool HasWildcard(const std::string & path);
/* Case sensitive match of a file mask ('*' and '?') against a file name.
 * A mask with no wildcard matches only exactly that name. */
bool MatchesMask(const std::string & mask, const std::string & name);

/* Formatting helpers used by the console output. */
std::string FormatSize(uint64_t size);
std::string FormatPermissions(unsigned long permissions);
std::string FormatFileTime(unsigned long time);
std::string FormatFileDate(unsigned long time);
std::string FormatFileClock(unsigned long time);

/*
 * Permission parsing, for 'chmod' and for '-permissions='. The values are
 * 'unsigned long' rather than mode_t on purpose: they come from and go to a
 * server, which carries the twelve permission bits plus the file type bits,
 * while mode_t on the local side is only the twelve permission bits.
 */

/* An octal permission value accepted by chmod: '600', '0600', '00600'. */
bool ParseOctalMode(const std::string & text, unsigned long & result);

/* A symbolic permission expression ('u+x', 'go-w', 'a=r,u+s') applied to
 * 'current'; see the comment in PathUtil.cpp for the accepted grammar. */
bool ParseSymbolicPermissions(const std::string & text, unsigned long current,
    bool isDirectory, unsigned long & result, std::string & error);

/* An octal mode or a symbolic expression, as 'chmod' accepts them. */
bool ParsePermissions(const std::string & text, unsigned long current,
    bool isDirectory, unsigned long & result, std::string & error);

} // namespace linscp

#endif /* LINSCP_PATHUTIL_H */
