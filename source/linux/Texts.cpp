#include "Texts.h"

#include "Platform.h"

#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <utility>

#include <libssh/libssh.h>

namespace linscp {
namespace Texts {

const char * const ProductName = "LinSCP";
const char * const ProductVersion = "1.0";

namespace {

#include "Translations.inc"

} // namespace

// Locale selection affects messages only: protocol output, numeric parsing and
// filenames must not inherit locale-dependent transformations. C/POSIX keep
// English output; an explicit LinSCP override is useful without installed OS
// locale data. Unknown locales fall back to English.
std::string Translate(const char * message,
    std::initializer_list<std::pair<const char *, std::string>> values)
{
    const char * selected = std::getenv("LINSCP_LANGUAGE");
    if (!selected || !*selected) selected = std::getenv("LC_ALL");
    if (!selected || !*selected) selected = std::getenv("LC_MESSAGES");
    if (!selected || !*selected) selected = std::getenv("LANG");
    std::string locale = selected ? selected : "en";
    const auto suffix = locale.find_first_of(".@");
    if (suffix != std::string::npos) locale.resize(suffix);
    const char * text = message;
    bool found = false;
    for (int pass = 0; pass < 2 && !found; ++pass)
    {
        for (const auto & entry : translations)
            if (locale == entry.locale && std::string(message) == entry.message)
            {
                text = entry.text;
                found = true;
                break;
            }
        const auto region = locale.find('_');
        if (region == std::string::npos) break;
        locale.resize(region);
    }
    // Substitute in one pass: a filename containing another placeholder must
    // never be interpreted as catalog syntax (nor as a printf format string).
    std::string result;
    for (size_t i = 0; text[i]; )
    {
        bool replaced = false;
        if (text[i] == '{') for (const auto & value : values)
        {
            const std::string token = "{" + std::string(value.first) + "}";
            if (std::string(text + i).compare(0, token.size(), token) == 0)
            {
                result += value.second;
                i += token.size();
                replaced = true;
                break;
            }
        }
        if (!replaced) result += text[i++];
    }
    return result;
}

std::string VersionLine()
{
    std::string result = std::string(ProductName) + " " + ProductVersion;
    result += " (libssh ";
    result += ssh_version(0);
    result += ")";
    return result;
}

std::string Usage()
{
    return Translate(
"LinSCP {version} - secure file transfer client\n"
"\n"
"  linscp [options] [sftp://[user[:password]@]host[:port]/[path]]\n"
"\n"
"Options:\n"
"  -script=FILE      execute commands from FILE ('-' reads stdin)\n"
"  -command=CMD      execute commands (separate several with ';')\n"
"  -literal          with -command, treat %...% in paths as literal text\n"
"  -rawsettings[=N]  session defaults as N NAME=VALUE arguments (also -shell)\n"
"  -hostkey=KEY      pin the host key (fingerprint or '*' for this connection)\n"
"  -password=PWD     password to use (prefer the LINSCP_PASSWORD variable)\n"
"  -privatekey=FILE  OpenSSH/PEM or PPK v2/v3 private key for authentication\n"
"  -passphrase=PWD   private-key passphrase (avoid exposing it in process lists)\n"
"  -convertkey=FILE  convert a PPK v2/v3 key (requires -output=FILE)\n"
"  -output=FILE      destination PEM file for -convertkey (no overwrite)\n"
"  -username=NAME    user name to authenticate with\n"
"  -port=NUMBER      port to connect to (default 22)\n"
"  -timeout=SECS     connection timeout in seconds (default 15)\n"
"  -clientcert=FILE  TLS client certificate for FTPS and WebDAVS\n"
"  -implicit[=on|off] / -explicit[=ON|OFF]  the TLS mode of an FTP session\n"
"  -passive[=on|off] choose the FTP data connection policy\n"
"  -log=FILE         log the session to FILE\n"
"  -loglevel=LEVEL   logging level: -1 reduced, 0 normal, 1 debug, 2 debug2\n"
"  -logsize=[N*]SIZE rotate the log at SIZE bytes, keeping N older files\n"
"  -xmllog=FILE      write an XML log of every command and operation to\n"
"                    FILE (upstream session format; passwords masked)\n"
"  -batch            never ask, abort instead\n"
"  -parameter VAL..  script parameters, for %1% .. %9%, %TIMESTAMP% and\n"
"                    %ENVIRONMENT% expansion in the commands\n"
"  -gui              launch the graphical Commander desktop interface\n"
"  -shell            open an interactive shell on the site given as\n"
"                    the argument; stdin and stdout are the raw byte\n"
"                    pipe of the shell, as the graphical client's\n"
"                    embedded terminal uses it\n"
"  -server           command server of the graphical client: one command\n"
"                    per line on stdin, 'LSCP-RESULT <code>' after each\n"
"  -verbose          print SSH event log messages\n"
"  -version          print the version and exit\n"
"  -help             print this help and exit\n"
"\n"
"Commands:\n"
"  open SITE         connect to a site (sftp://user@host:port/path)\n"
"  close [INDEX]     disconnect the open session, or session INDEX\n"
"  cd DIR            change the remote directory\n"
"  pwd               print the remote directory\n"
"  ls [-al1] [DIR]   list remote files\n"
"  versions [OBJECT] list S3 object versions and delete markers\n"
"  lcd DIR           change the local directory\n"
"  lpwd              print the local directory\n"
"  lls [DIR[/MASK]]  list local files with date, time and size\n"
"  get [opts] REMOTE [LOCAL]  download file(s) or directories\n"
"  put [opts] LOCAL [REMOTE]  upload file(s) or directories\n"
"                    both: -r -delete -neweronly -resume -append -preservetime\n"
"                    -speed=KB -transfer=binary|ascii|automatic -filemask=MASK\n"
"                    -resumesupport=on|off|KB -rawtransfersettings[=N]\n"
"                    -permissions[=OCTAL] -nopermissions\n"
"                    -versionid=ID (S3 get/rm; versions lists history)\n"
"  synchronize local|remote|both [LOCAL [REMOTE]] [switches]\n"
"                    synchronize directories: -delete -preview\n"
"                    -nonrecursive -filemask=MASK\n"
"                    -criteria=time|size|checksum|either|both|none\n"
"  keepuptodate [LOCAL [REMOTE]] [switches]\n"
"                    reflect local changes on the remote side; the local\n"
"                    tree is watched, -interval=SECS polls instead\n"
"                    (-count=N bounds the passes; Ctrl-C stops watching)\n"
"  edit FILE         edit a remote file in an external editor\n"
"                    (-force, -keep, -editor=COMMAND)\n"
"  session [INDEX]   list the open sessions, or switch to INDEX\n"
"  sessions [NAME]   list stored sites; NAME opens one, and\n"
"                    (also: sessions export FILE, sessions import FILE)\n"
"  savesession NAME  store the current connection as a named session\n"
"                    (-preset=NAME stores its transfer preset)\n"
"  rmsession NAME    forget a stored session\n"
"  presets           list the transfer presets; savepreset NAME K=V...\n"
"                    stores one, rmspreset NAME removes one\n"
"  rm FILE           remove remote file(s)\n"
"  rmdir DIR         remove a remote directory\n"
"  mkdir [-parents] DIR  create a remote directory (parents if requested)\n"
"  mv FROM TO        move/rename a remote file\n"
"  chmod MODE FILE [FILE...] [-recursive]\n"
"                    change remote permissions; MODE is octal (644) or\n"
"                    symbolic (u+x, a=r,go-w)\n"
"  copyid [KEYFILE]  add the public key of KEYFILE, or of the session key,\n"
"                    to the server's ~/.ssh/authorized_keys\n"
"  stat FILE         print the listing line of a remote path\n"
"  attr FILE         print remote file attributes, key/value\n"
"  terminal          open an interactive shell on the server\n"
"  echo [MESSAGE]    display text message\n"
"  option confirm|batch|resume|editor|editmaxsize|transfer|preset VALUE\n"
"                    configure session options (preset NAME makes a\n"
"                    transfer preset the default, 'option preset off' clears)\n"
"  binary / ascii    select the transfer mode of the following commands\n"
"  help              list the commands (alias: man)\n"
"  exit              end the session\n", {{"version", ProductVersion}});
}

std::string CannotOpenSession(const std::string & host, const std::string & reason)
{
    return Translate("Cannot open session to {host}: {reason}", {{"host", host}, {"reason", reason}});
}

std::string ConnectionClosed()
{
    return Translate("Connection has been unexpectedly closed.");
}

std::string HostKeyUnknown(const std::string & host, int port,
    const std::string & keyType, const std::string & fingerprint)
{
    return Translate("The host key of {host} (port {port}) is not cached.\n  {type} key fingerprint: {fingerprint}\nIf you expected a different fingerprint, do not continue.",
        {{"host", host}, {"port", std::to_string(port)}, {"type", keyType},
        {"fingerprint", fingerprint}});
}

std::string HostKeyMismatch(const std::string & host, int port,
    const std::string & keyType, const std::string & fingerprint)
{
    return Translate("The host key of {host} (port {port}) does not match the cached key.\n  {type} key fingerprint: {fingerprint}\nThe connection may be intercepted; refusing to continue.",
        {{"host", host}, {"port", std::to_string(port)}, {"type", keyType},
        {"fingerprint", fingerprint}});
}

std::string HostKeyUnexpected(const std::string & host, int port,
    const std::string & keyType, const std::string & fingerprint,
    const std::string & expected)
{
    return Translate("The host key of {host} (port {port}) is not the expected one.\n  {type} key fingerprint: {fingerprint}\n  expected fingerprint:           {expected}\nThe connection may be intercepted; refusing to continue.",
        {{"host", host}, {"port", std::to_string(port)}, {"type", keyType},
        {"fingerprint", fingerprint}, {"expected", expected}});
}

std::string HostKeyCached(const std::string & host, int port)
{
    return Translate("Host key of {host} (port {port}) verified from cache.", {{"host", host}, {"port", std::to_string(port)}});
}

std::string PasswordPrompt(const std::string & userName, const std::string & host)
{
    return Translate("{user}@{host}'s password: ", {{"user", userName}, {"host", host}});
}

std::string NotConnected()
{
    return Translate("Not connected. Use 'open' to connect to a site first.");
}

std::string ReadingDirectory(const std::string & path)
{
    return Translate("Reading directory {path}...", {{"path", path}});
}

std::string DirectoryRead(int count)
{
    return Translate(count == 1 ? "{count} entry" : "{count} entries", {{"count", std::to_string(count)}});
}

std::string CannotReadDirectory(const std::string & path, const std::string & reason)
{
    return Translate("Cannot read directory '{path}'. {reason}", {{"path", path}, {"reason", reason}});
}

std::string RetrievingFile(const std::string & remote, const std::string & local)
{
    return Translate("Retrieving {remote} to {local}", {{"remote", remote}, {"local", local}});
}

std::string UploadingFile(const std::string & local, const std::string & remote)
{
    return Translate("Uploading {local} to {remote}", {{"local", local}, {"remote", remote}});
}

std::string FileTransferred(const std::string & name, uint64_t size)
{
    return name + Translate(" [{size} bytes]", {{"size", std::to_string(size)}});
}

std::string TransferFailed(const std::string & name, const std::string & reason)
{
    return Translate("Transfer of '{name}' failed. {reason}", {{"name", name}, {"reason", reason}});
}

std::string RemoteError(const std::string & operation, const std::string & path,
    const std::string & reason)
{
    return Translate("Cannot {operation} '{path}'. {reason}", {{"operation", Translate(operation.c_str())}, {"path", path}, {"reason", reason}});
}

std::string LocalError(const std::string & operation, const std::string & path,
    const std::string & reason)
{
    return Translate("Local {operation} of '{path}' failed. {reason}", {{"operation", Translate(operation.c_str())}, {"path", path}, {"reason", reason}});
}

std::string UnknownCommand(const std::string & command)
{
    return Translate("Unknown command '{command}'. Type 'help' for a list of commands.", {{"command", command}});
}

std::string WrongArguments(const std::string & command, const std::string & hint)
{
    return Translate("Wrong arguments of '{command}' command. {hint}", {{"command", command}, {"hint", hint}});
}

std::string SessionOpened(const std::string & host)
{
    return Translate("Session '{host}' opened.", {{"host", host}});
}

std::string SessionClosed(const std::string & name)
{
    return Translate("Session '{name}' closed.", {{"name", name}});
}

std::string DirectoryCreated(const std::string & path)
{
    return Translate("Directory '{path}' created.", {{"path", path}});
}

std::string FileRemoved(const std::string & path)
{
    return Translate("Removed '{path}'.", {{"path", path}});
}

std::string FileMoved(const std::string & from, const std::string & to)
{
    return Translate("Moved '{from}' to '{to}'.", {{"from", from}, {"to", to}});
}

std::string PermissionsChanged(const std::string & path, const std::string & mode)
{
    return Translate("Permissions of '{path}' changed to {mode}.", {{"path", path}, {"mode", mode}});
}

std::string ChecksumResult(const std::string & algorithm,
    const std::string & hash, const std::string & path)
{
    return Translate("{algorithm} checksum of '{path}': {hash}", {{"algorithm", algorithm}, {"path", path}, {"hash", hash}});
}

std::string LockAcquired(const std::string & path)
{
    return Translate("Lock acquired on '{path}'.", {{"path", path}});
}

std::string LockReleased(const std::string & path)
{
    return Translate("Lock released on '{path}'.", {{"path", path}});
}

std::string PropertySet(const std::string & name, const std::string & path)
{
    return Translate("Set {name} on {path}.", {{"name", name}, {"path", path}});
}

std::string PropertyNotSet(const std::string & name, const std::string & path)
{
    return Translate("{name} is not set on {path}.", {{"name", name}, {"path", path}});
}

std::string PropertyValue(const std::string & name, const std::string & value)
{
    return Translate("{name}={value}", {{"name", name}, {"value", value}});
}

std::string EtagSet(const std::string & type, const std::string & etag,
    const std::string & path)
{
    return Translate("{type}: {etag} on {path}.", {{"type", type}, {"etag", etag}, {"path", path}});
}

std::string EtagCleared(const std::string & path)
{
    return Translate("Cleared ETag precondition on {path}.", {{"path", path}});
}

std::string NoEtag(const std::string & path)
{
    /* The path is part of the answer: a script that asked about several
     * has to tell which one the server has not got, and the sibling
     * message for a resource the server did report on names it too. */
    return Translate("No ETag: '{path}' does not exist.", {{"path", path}});
}

std::string NoEtagReported(const std::string & path)
{
    return Translate("The server reported no ETag for '{path}'.",
        {{"path", path}});
}

std::string EtagNotAvailable(const std::string & protocol)
{
    return Translate("(ETag not available for {protocol} protocol.)", {{"protocol", protocol}});
}

std::string SyncPlanHeader(int count)
{
    return Translate("{count} differences found.", {{"count", std::to_string(count)}});
}

std::string SyncDirection(const std::string & direction)
{
    return Translate("Synchronizing {direction}...", {{"direction", direction}});
}

std::string KeepUpToDateStarting(int interval)
{
    return Translate("Watching for changes (interval: {interval}s)...", {{"interval", std::to_string(interval)}});
}

std::string KeepUpToDatePass(int pass)
{
    return Translate("Pass {pass}...", {{"pass", std::to_string(pass)}});
}

std::string EditingFile(const std::string & path)
{
    return Translate("Editing '{path}'...", {{"path", path}});
}

std::string EditConflict(const std::string & path)
{
    return Translate("'{path}' was modified on the server since it was opened.", {{"path", path}});
}

std::string CopyIdInstalled(const std::string & path)
{
    return Translate("Public key installed in '{path}'.", {{"path", path}});
}

std::string CopyIdAlreadyInstalled()
{
    return Translate("The key is already installed.");
}

std::string LinkCreated(const std::string & target, const std::string & link)
{
    return Translate("Symbolic link created: {link} -> {target}.", {{"target", target}, {"link", link}});
}

std::string SessionListed(int index, const std::string & name)
{
    return Translate("  {index} {name}", {{"index", std::to_string(index)}, {"name", name}});
}

std::string PresetListed(const std::string & name)
{
    return Translate("  {name}", {{"name", name}});
}

std::string PresetSaved(const std::string & name)
{
    return Translate("Preset '{name}' saved.", {{"name", name}});
}

std::string PresetRemoved(const std::string & name)
{
    return Translate("Preset '{name}' removed.", {{"name", name}});
}

std::string OptionSet(const std::string & name, const std::string & value)
{
    return Translate("Option {name} set to '{value}'.", {{"name", name}, {"value", value}});
}

std::string OptionValue(const std::string & name, const std::string & value)
{
    return Translate("{name} = {value}", {{"name", name}, {"value", value}});
}

std::string TerminalOpening()
{
    return Translate("Opening terminal...");
}

} // namespace Texts
} // namespace linscp
