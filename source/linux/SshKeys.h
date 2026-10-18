/*
 * SshKeys: the SSH host key cache and key-file helpers of the libssh
 * transport. This replaces the parts of the old PuTTY platform glue
 * (PuttyGlue.cpp) that the front end still needs: the on-disk host key
 * cache in the configuration directory, and turning a key file into the
 * 'authorized_keys' line the 'copyid' command installs.
 *
 * The cache keeps the format the PuTTY-based client wrote, one line per
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
 * ('algorithm base64-blob comment'), for the 'copyid' command. An
 * OpenSSH public key file, or a private key in OpenSSH/PEM format, is
 * accepted. PuTTY .ppk files are not: libssh cannot read them, and the
 * error says how to convert one. Returns false with 'error' set when
 * the file holds no usable SSH-2 public key.
 */
bool PublicKeyAuthorizedLine(const std::string & keyFile, std::string & line,
    std::string & error,
    const std::string & suppliedPassphrase = std::string());

/* True for a PuTTY private key file name ('.ppk'). */
bool IsPuttyKeyFile(const std::string & keyFile);

} // namespace linscp

#endif /* LINSCP_SSHKEYS_H */
