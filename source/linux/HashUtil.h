/*
 * HashUtil: file digests for 'checksum', using OpenSSL EVP plus CRC-32.
 * Compiled as C to keep its small crypto API easy to use from C modules.
 */

#ifndef LINSCP_HASHUTIL_H
#define LINSCP_HASHUTIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest digest this API returns (SHA-512). */
#define LSCP_HASH_HEX_SIZE 129

/* Algorithms: "sha-256", "sha-1", "md5", "crc32" (case insensitive,
 * with or without the dash: sha256 == sha-256). Returns 0 on success
 * and writes the lowercase hex digest; -1 for an unknown algorithm or
 * a file error, with lscp_hash_error() holding the reason. */
int lscp_hash_file(const char * algorithm, const char * path,
    char * hex, size_t hexSize);
const char * lscp_hash_error(void);

/* HMAC-SHA256 of 'data' under 'key' through OpenSSL (the PRF used for
 * sessions-file password encryption). Writes 32 bytes to 'out'; 'outSize'
 * must be at least 32. Returns 0 on success. */
int lscp_hmac_sha256(const void * key, size_t keyLen,
    const void * data, size_t dataLen, unsigned char * out, size_t outSize);

/* One-shot SHA-256 of 'data' through OpenSSL: writes 32 bytes to
 * 'out'; 'outSize' must be at least 32. Returns 0 on success. */
int lscp_sha256(const void * data, size_t dataLen,
    unsigned char * out, size_t outSize);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LINSCP_HASHUTIL_H */
