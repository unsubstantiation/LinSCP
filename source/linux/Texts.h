/*
 * Texts: user visible strings of the front end.
 *
 * Upstream keeps its strings in resource files so that they can be
 * translated; the console client keeps the same discipline with one
 * module holding shared messages, with compiled UTF-8 catalogs for a subset.
 * See docs/localization.md for supported scope and locale selection.
 */

#ifndef LINSCP_TEXTS_H
#define LINSCP_TEXTS_H

#include <cstdint>
#include <string>
#include <initializer_list>
#include <utility>

namespace linscp {
namespace Texts {

extern const char * const ProductName;
extern const char * const ProductVersion;

// Translate only explicitly identified human-facing messages, never arbitrary
// command output, paths or wire protocol data. Values are substituted once.
std::string Translate(const char * message,
    std::initializer_list<std::pair<const char *, std::string>> values = {});
std::string VersionLine();
std::string Usage();

std::string CannotOpenSession(const std::string & host, const std::string & reason);
std::string ConnectionClosed();
std::string HostKeyUnknown(const std::string & host, int port,
    const std::string & keyType, const std::string & fingerprint);
std::string HostKeyMismatch(const std::string & host, int port,
    const std::string & keyType, const std::string & fingerprint);
std::string HostKeyUnexpected(const std::string & host, int port,
    const std::string & keyType, const std::string & fingerprint,
    const std::string & expected);
std::string HostKeyCached(const std::string & host, int port);
std::string PasswordPrompt(const std::string & userName, const std::string & host);
std::string NotConnected();
std::string ReadingDirectory(const std::string & path);
std::string DirectoryRead(int count);
std::string CannotReadDirectory(const std::string & path, const std::string & reason);
std::string RetrievingFile(const std::string & remote, const std::string & local);
std::string UploadingFile(const std::string & local, const std::string & remote);
std::string FileTransferred(const std::string & name, uint64_t size);
std::string TransferFailed(const std::string & name, const std::string & reason);
std::string RemoteError(const std::string & operation, const std::string & path,
    const std::string & reason);
std::string LocalError(const std::string & operation, const std::string & path,
    const std::string & reason);
std::string UnknownCommand(const std::string & command);
std::string WrongArguments(const std::string & command, const std::string & hint);

/* --- Additional translatable strings for command help and status --- */
std::string SessionOpened(const std::string & host);
std::string SessionClosed(const std::string & name);
std::string DirectoryCreated(const std::string & path);
std::string FileRemoved(const std::string & path);
std::string FileMoved(const std::string & from, const std::string & to);
std::string PermissionsChanged(const std::string & path, const std::string & mode);
std::string ChecksumResult(const std::string & algorithm,
    const std::string & hash, const std::string & path);
std::string LockAcquired(const std::string & path);
std::string LockReleased(const std::string & path);
std::string PropertySet(const std::string & name, const std::string & path);
std::string PropertyNotSet(const std::string & name, const std::string & path);
std::string PropertyValue(const std::string & name, const std::string & value);
std::string EtagSet(const std::string & type, const std::string & etag,
    const std::string & path);
std::string EtagCleared(const std::string & path);
std::string NoEtag(const std::string & path);
std::string NoEtagReported(const std::string & path);
std::string EtagNotAvailable(const std::string & protocol);
std::string SyncPlanHeader(int count);
std::string SyncDirection(const std::string & direction);
std::string KeepUpToDateStarting(int interval);
std::string KeepUpToDatePass(int pass);
std::string EditingFile(const std::string & path);
std::string EditConflict(const std::string & path);
std::string CopyIdInstalled(const std::string & path);
std::string CopyIdAlreadyInstalled();
std::string LinkCreated(const std::string & target, const std::string & link);
std::string SessionListed(int index, const std::string & name);
std::string PresetListed(const std::string & name);
std::string PresetSaved(const std::string & name);
std::string PresetRemoved(const std::string & name);
std::string OptionSet(const std::string & name, const std::string & value);
std::string OptionValue(const std::string & name, const std::string & value);
std::string TerminalOpening();

} // namespace Texts
} // namespace linscp

#endif /* LINSCP_TEXTS_H */
