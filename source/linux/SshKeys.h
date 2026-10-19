/*
 * SshKeys: the SSH host key cache and key-file helpers of the libssh
 * transport: the on-disk host key cache in the configuration directory,
 * and turning a supported key file into the
 * 'authorized_keys' line the 'copyid' command installs.
 *
 * The cache keeps the format the earlier client versions wrote, one line per
 * key:
 *
 *     <hostname>@<port> <key type> <base64 key blob>
 *
 * so a cache written by an older build is still read (and still matches:
 * both sides store the SSH wire blob of the public key, base64 encoded).
 */

#ifndef LINSCP_SSHKEYS_H
#define LINSCP_SSHKEYS_H

#include <string>

namespace linscp {

/*
 * Looks up the cached host key for 'hostname'/'port'/'keytype' ('keytype'
 * may be NULL to accept any type). Returns 1 when a cached key equals
 * 'key', 0 when no key is cached for this host, and -1 when a cached key
 * exists and differs.
 */
int CheckCachedHostKey(const char * hostname, int port,
    const char * keytype, const char * key);

/* Stores (or replaces) the host key in the cache. */
void StoreHostKey(const char * hostname, int port,
    const char * keytype, const char * key);

/*
 * Formats the public half of 'keyFile' as one 'authorized_keys' line
 * ('algorithm base64-blob comment'), for the 'copyid' command. OpenSSH
 * public/private keys and PPK v2/v3 files are accepted. Returns false with
 * 'error' set when the file holds no usable SSH-2 public key.
 */
bool PublicKeyAuthorizedLine(const std::string & keyFile, std::string & line,
    std::string & error,
    const std::string & suppliedPassphrase = std::string());

/* True when the file begins with the PPK v2/v3 container marker. */
bool IsPpkKeyFile(const std::string & keyFile);

} // namespace linscp

#endif /* LINSCP_SSHKEYS_H */
