/*
 * SessionStore: the persistent site manager.
 *
 * A stored session ("site") keeps everything needed to connect again:
 * protocol, host, port, user name, key file, expected host key and the
 * directories to start in. Sessions live in an INI-style file in the
 * per-user configuration directory, one section per session:
 *
 *   [Servers/web.example.com]
 *   protocol=sftp
 *   host=web.example.com
 *   port=22
 *   username=alice
 *   remote_directory=/srv/www
 *   local_directory=/home/alice/www
 *   hostkey=SHA256:...
 *   last_used=1760000000
 *
 * The section name is the session name and may contain '/', which the
 * graphical client shows as a folder tree. Passwords are never written
 * unless the user asks for it explicitly ('savesession -password=...'),
 * and then only encrypted under a key file next to this one
 * ('sessions.key', created on first use with the permissions of the
 * user); a value that still reads as plaintext came from before the
 * encryption existed and is upgraded on the next save.
 *
 * The graphical client reads the same file, which is why the format is
 * deliberately simple and stable - and why the encryption carries a
 * version prefix the other side understands.
 */

#ifndef LINSCP_SESSIONSTORE_H
#define LINSCP_SESSIONSTORE_H

#include <string>
#include <vector>

#include "Session.h"

namespace linscp {

struct StoredSession
{
    std::string name;
    std::string protocol;
    std::string hostName;
    int portNumber;
    std::string userName;
    std::string privateKeyFile;
    /* Expected host key: empty = cache/ask, "*" = accept any. */
    std::string hostKey;
    std::string remoteDirectory;
    std::string localDirectory;
    /*
     * Saved only when explicitly requested; empty otherwise. When the
     * file holds an encrypted password, 'password' receives the
     * decrypted text at load; if that fails (no key file, wrong key,
     * tampered value) 'password' stays empty, 'passwordStored' keeps
     * true, 'passwordRaw' preserves the encrypted value so a save does
     * not destroy it, and 'passwordError' says why it is unusable.
     */
    std::string password;
    bool passwordStored;
    std::string passwordRaw;
    std::string passwordError;
    /* Seconds since the epoch of the last successful connect, 0 = never. */
    unsigned long long lastUsed;
    /* Transfer preset selected for this site ('savesession -preset='),
     * empty = none; 'open <name>' makes it the session's preset. */
    std::string preset;
    /*
     * The proxy of this site, in upstream's session-setting vocabulary
     * ('open <name> -rawsettings ProxyMethod=SOCKS5 ProxyHost=...').
     * Its password is stored encrypted under the same key file as the
     * session password; a value this machine cannot decrypt stays in
     * 'proxyPasswordRaw' - so that re-saving the site does not destroy
     * it - with the reason in 'proxyPasswordError'.
     */
    ProxySettings proxy;
    std::string proxyPasswordRaw;
    /* Why the stored proxy cannot be used: a password this machine cannot
     * decrypt, or a method name the file does not hold any more. Empty
     * when the proxy is usable; 'open <name>' refuses a site that has one,
     * because connecting without the proxy the site was stored with would
     * send the session somewhere else than its user asked for. */
    std::string proxyError;
    /*
     * The FTP engine's policy and the TLS policy of the site, stored under
     * the same names '-rawsettings' takes (FtpPasvMode, FtpUseMlsd, Ftps,
     * MinTlsVersion, TlsCertificateFile, ...). Only the values that differ
     * from the defaults are written, so a plain site keeps a plain file.
     */
    FtpSettings ftp;
    TlsSettings tls;
    S3Settings s3;
    SshTunnelSettings tunnel;
    /* Preserve unreadable ciphertext across unrelated saves, but never
     * connect with a missing/incorrect jump-host credential. */
    std::string tunnelPasswordRaw;
    std::string tunnelPassphraseRaw;
    std::string tunnelError;
    /* Why a stored FTP/TLS/S3 setting cannot be used, if one cannot: the file
     * then holds a value this build does not accept (a newer version's
     * setting, or a typo), and 'open' says so instead of connecting with a
     * policy nobody asked for. */
    std::string settingError;

    StoredSession() : portNumber(0), passwordStored(false), lastUsed(0) {}
};

class SessionStore
{
public:
    /* The file is read on construction; a missing or unreadable file is
     * not an error, it simply leaves the store empty. */
    SessionStore();
    explicit SessionStore(const std::string & path);

    /* Configuration directory + "sessions.ini". */
    static std::string DefaultPath();
    const std::string & Path() const { return mPath; }
    /* The key file that pairs with Path(): '<path without .ini>.key'. */
    const std::string & KeyPath() const { return mKeyPath; }

    /*
     * The stored-password format, shared with the graphical client
     * (source/gui/linscp_crypto.py produces and consumes the same
     * bytes): 'lscp1$' + base64(nonce[16] || ciphertext || tag[32]).
     * The keystream is HMAC-SHA256 of the nonce and a block counter
     * under a key derived from the key file; the tag is HMAC-SHA256
     * over the format label, the nonce and the ciphertext under a
     * second derived key (encrypt-then-MAC, each direction domain
     * separated from the raw key-file bytes). 'key' is the raw
     * 32-byte content of the key file. Static so that tests can hold
     * both directions against one key.
     */
    static bool EncryptPassword(const std::string & plain,
        const std::string & key, std::string & encoded, std::string & error);
    static bool DecryptPassword(const std::string & encoded,
        const std::string & key, std::string & plain, std::string & error);

    /* Reloads the file, discarding unsaved changes. */
    bool Load(std::string & error);
    /* Writes the file, creating its directory with user-only access.
     * Passwords are encrypted before the file is opened, so a failure
     * to encrypt leaves the previous file intact. */
    bool Save(std::string & error) const;

    const std::vector<StoredSession> & Sessions() const { return mSessions; }
    bool Empty() const { return mSessions.empty(); }

    /* Looks a session up by name, case-insensitively when there is no
     * exact match. Returns NULL when there is no such session. */
    const StoredSession * Find(const std::string & name) const;

    bool AddOrUpdate(const StoredSession & session, std::string & error);
    bool Remove(const std::string & name, std::string & error);
    bool Rename(const std::string & from, const std::string & to, std::string & error);

    /* Folder-tree helpers: session names containing '/' form a folder
     * hierarchy ('Prod/Web/app1' is in folders 'Prod' and 'Prod/Web'). */
    std::vector<std::string> Folders() const;
    std::vector<StoredSession> SessionsInFolder(const std::string & folder) const;
    int RemoveFolder(const std::string & folder, std::string & error);

    /* Reads the sessions of 'path' into this store: 'merge' keeps the
     * sessions that are already here, otherwise they are replaced.
     * Returns the number of sessions that were imported. */
    int ImportFile(const std::string & path, bool merge, std::string & error);
    /* Writes every session to 'path'. */
    bool ExportFile(const std::string & path, std::string & error);

    /* A stored session as connection options; 'defaults' fills what the
     * session does not specify. */
    static SessionOptions ToSessionOptions(const StoredSession & session,
        const SessionOptions & defaults);
    /* The current connection as a session to store. */
    static StoredSession FromSessionOptions(const std::string & name,
        const SessionOptions & options, const std::string & remoteDirectory,
        const std::string & localDirectory);

    /* Validates a name: not empty, no control characters and no leading
     * or trailing white space. */
    static bool IsValidName(const std::string & name);

private:
    SessionStore(const SessionStore &);
    SessionStore & operator=(const SessionStore &);

    std::vector<StoredSession> mSessions;
    std::string mPath;
    std::string mKeyPath;
};

} // namespace linscp

#endif /* LINSCP_SESSIONSTORE_H */
