/*
 * PPK private-key interoperability over the libssh transport. This module
 * parses the documented PPK v2/v3 container, verifies its MAC, decrypts its
 * private section, and emits a temporary OpenSSH-compatible PEM for libssh.
 */
#ifndef LINSCP_PPKKEY_H
#define LINSCP_PPKKEY_H

#include <string>

namespace linscp {

bool IsPpkKeyFile(const std::string & path);
/* Verifies the PPK MAC and extracts its SSH public key. */
bool PpkPublicAuthorizedLine(const std::string & path, const std::string & passphrase,
    std::string & line, std::string & error);
/* Decrypts and verifies a PPK private key, returning PEM text in memory. */
bool PpkPrivateKeyPem(const std::string & path,
    const std::string & passphrase, std::string & pem, std::string & error);
/* Writes a PEM key without replacing the destination; preserves encryption. */
bool ConvertPpkToOpenSsh(const std::string & input,
    const std::string & output, const std::string & passphrase,
    std::string & error);

} // namespace linscp

#endif /* LINSCP_PPKKEY_H */
