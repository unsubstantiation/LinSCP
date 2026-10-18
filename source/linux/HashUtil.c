/*
 * HashUtil: file digests for 'checksum', through OpenSSL's EVP API (the
 * crypto library libssh already links), plus CRC-32. This replaces the
 * hash algorithms of the old shared PuTTY core.
 */

#include "HashUtil.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static char g_hash_error[256];

static void set_hash_error(const char * text)
{
    snprintf(g_hash_error, sizeof(g_hash_error), "%s", text);
}

const char * lscp_hash_error(void)
{
    return g_hash_error;
}

/* CRC-32 (ISO 3309), table driven. */
static uint32_t lscp_crc32_update(uint32_t crc, const unsigned char * data,
    size_t length)
{
    static uint32_t table[256];
    static int table_ready = 0;
    size_t i;
    if (!table_ready)
    {
        uint32_t n;
        int k;
        for (n = 0; n < 256; n++)
        {
            uint32_t c = n;
            for (k = 0; k < 8; k++)
            {
                c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
            }
            table[n] = c;
        }
        table_ready = 1;
    }
    crc = crc ^ 0xffffffffu;
    for (i = 0; i < length; i++)
    {
        crc = table[(crc ^ data[i]) & 0xffu] ^ (crc >> 8);
    }
    return crc ^ 0xffffffffu;
}

static int algorithm_matches(const char * name, const char * canonical)
{
    /* 'name' with dashes removed, lower-cased, against 'canonical'. */
    char cleaned[32];
    size_t out = 0;
    size_t i;
    for (i = 0; name[i] != '\0' && out + 1 < sizeof(cleaned); i++)
    {
        if (name[i] != '-' && name[i] != '_')
        {
            cleaned[out++] = (char)tolower((unsigned char)name[i]);
        }
    }
    cleaned[out] = '\0';
    return strcmp(cleaned, canonical) == 0;
}

int lscp_hash_file(const char * algorithm, const char * path,
    char * hex, size_t hexSize)
{
    static const char digits[] = "0123456789abcdef";
    const EVP_MD * md = NULL;
    int use_crc32 = 0;
    FILE * file;
    unsigned char buffer[16384];
    size_t got;
    size_t i;

    g_hash_error[0] = '\0';
    if (hex == NULL || hexSize == 0)
    {
        set_hash_error("No room for the digest.");
        return -1;
    }
    hex[0] = '\0';

    if (algorithm_matches(algorithm, "sha256"))
    {
        md = EVP_sha256();
    }
    else if (algorithm_matches(algorithm, "sha512"))
    {
        md = EVP_sha512();
    }
    else if (algorithm_matches(algorithm, "sha1"))
    {
        md = EVP_sha1();
    }
    else if (algorithm_matches(algorithm, "md5"))
    {
        md = EVP_md5();
    }
    else if (algorithm_matches(algorithm, "crc32"))
    {
        use_crc32 = 1;
    }
    else
    {
        set_hash_error("Unknown checksum algorithm (use sha-256, sha-1, md5 or crc32).");
        return -1;
    }

    file = fopen(path, "rb");
    if (file == NULL)
    {
        snprintf(g_hash_error, sizeof(g_hash_error), "Cannot open '%s': %s",
            path, strerror(errno));
        return -1;
    }

    if (use_crc32)
    {
        uint32_t crc = 0;
        while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
        {
            crc = lscp_crc32_update(crc, buffer, got);
        }
        if (ferror(file))
        {
            snprintf(g_hash_error, sizeof(g_hash_error), "Cannot read '%s': %s",
                path, strerror(errno));
            fclose(file);
            return -1;
        }
        fclose(file);
        if (hexSize < 9)
        {
            set_hash_error("No room for the digest.");
            return -1;
        }
        snprintf(hex, hexSize, "%08x", crc);
        return 0;
    }

    {
        EVP_MD_CTX * ctx = EVP_MD_CTX_new();
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;
        int ok = 1;
        if (ctx == NULL || EVP_DigestInit_ex(ctx, md, NULL) != 1)
        {
            ok = 0;
        }
        while (ok && (got = fread(buffer, 1, sizeof(buffer), file)) > 0)
        {
            if (EVP_DigestUpdate(ctx, buffer, got) != 1)
            {
                ok = 0;
            }
        }
        if (ok && ferror(file))
        {
            snprintf(g_hash_error, sizeof(g_hash_error),
                "Cannot read '%s': %s", path, strerror(errno));
            ok = 0;
        }
        if (ok && EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1)
        {
            ok = 0;
        }
        EVP_MD_CTX_free(ctx);
        fclose(file);
        if (!ok)
        {
            if (g_hash_error[0] == '\0')
            {
                set_hash_error("Cannot calculate the digest.");
            }
            return -1;
        }
        if (hexSize < (size_t)digestLen * 2 + 1)
        {
            set_hash_error("No room for the digest.");
            return -1;
        }
        for (i = 0; i < digestLen; i++)
        {
            hex[i * 2] = digits[digest[i] >> 4];
            hex[i * 2 + 1] = digits[digest[i] & 0x0f];
        }
        hex[digestLen * 2] = '\0';
        return 0;
    }
}

int lscp_hmac_sha256(const void * key, size_t keyLen,
    const void * data, size_t dataLen, unsigned char * out, size_t outSize)
{
    unsigned int len = 0;
    if (out == NULL || outSize < SHA256_DIGEST_LENGTH)
    {
        return -1;
    }
    if (HMAC(EVP_sha256(), key, (int)keyLen,
            (const unsigned char *)data, dataLen, out, &len) == NULL ||
        len != SHA256_DIGEST_LENGTH)
    {
        return -1;
    }
    return 0;
}

int lscp_sha256(const void * data, size_t dataLen,
    unsigned char * out, size_t outSize)
{
    if (out == NULL || outSize < SHA256_DIGEST_LENGTH)
    {
        return -1;
    }
    if (SHA256((const unsigned char *)data, dataLen, out) == NULL)
    {
        return -1;
    }
    return 0;
}
