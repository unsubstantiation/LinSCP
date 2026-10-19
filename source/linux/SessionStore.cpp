/*
 * SessionStore: reading and writing the persistent site list.
 *
 * The on-disk format is intentionally plain INI with '=' separated
 * values, one section per session, so that the graphical client (which
 * reads the same file from Python) and a user with a text editor see
 * the same thing. Values escape '\\', newlines, carriage returns and
 * tabs; everything else is stored verbatim, UTF-8 encoded.
 *
 * A stored password is written encrypted, never in the clear: the value
 * is 'lscp1$' + base64(nonce || ciphertext || tag) under a 32-byte key
 * kept in a sibling key file ('sessions.key'). The construction and its
 * labels are mirrored in source/gui/linscp_crypto.py; both sides must
 * produce and consume the same bytes, and the test suites hold them to
 * that with shared test vectors. A plaintext password that predates the
 * encryption is still read and is rewritten encrypted on the next save.
 */

#include "SessionStore.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>

#include <algorithm>

#include "HashUtil.h"
#include "LocalFs.h"
#include "PathUtil.h"
#include "Platform.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace linscp {

namespace {

/* The stored-password value: version prefix, then base64. */
const char * const kPasswordPrefix = "lscp1$";
/* The domain separator of the authenticator, fed to HMAC as data. */
const char * const kTagLabel = "lscp1";
/* Key derivation labels: one key per direction, never the raw file
 * bytes. Must match source/gui/linscp_crypto.py exactly. */
const char * const kEncKeyLabel = "LinSCP sessions file v1 encryption key";
const char * const kMacKeyLabel = "LinSCP sessions file v1 authentication key";
const size_t kKeyBytes = 32;
const size_t kNonceBytes = 16;
const size_t kTagBytes = 32;
const size_t kMaxPasswordBytes = 4096;

bool StartsWith(const std::string & text, const char * prefix)
{
    const size_t len = strlen(prefix);
    return text.size() >= len && text.compare(0, len, prefix) == 0;
}

std::string Trim(const std::string & text)
{
    size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
    {
        return std::string();
    }
    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::string EscapeValue(const std::string & text)
{
    std::string result;
    for (size_t i = 0; i < text.size(); i++)
    {
        const char c = text[i];
        if (c == '\\')
        {
            result += "\\\\";
        }
        else if (c == '\n')
        {
            result += "\\n";
        }
        else if (c == '\r')
        {
            result += "\\r";
        }
        else if (c == '\t')
        {
            result += "\\t";
        }
        else
        {
            result += c;
        }
    }
    return result;
}

std::string UnescapeValue(const std::string & text)
{
    std::string result;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] != '\\' || i + 1 == text.size())
        {
            result += text[i];
            continue;
        }
        const char c = text[++i];
        result += c == 'n' ? '\n' : c == 'r' ? '\r' : c == 't' ? '\t' : c;
    }
    return result;
}

std::string Lower(const std::string & text)
{
    std::string result = text;
    for (size_t i = 0; i < result.size(); i++)
    {
        if (result[i] >= 'A' && result[i] <= 'Z')
        {
            result[i] = static_cast<char>(result[i] - 'A' + 'a');
        }
    }
    return result;
}

/* The stored key of a site setting and the raw setting behind it. */
struct SiteSettingKey
{
    const char * key;
    const char * setting;
};

const SiteSettingKey kSiteSettingKeys[] = {
    { "tunnel", "Tunnel" },
    { "tunnel_host", "TunnelHostName" },
    { "tunnel_port", "TunnelPortNumber" },
    { "tunnel_username", "TunnelUserName" },
    { "tunnel_private_key", "TunnelPublicKeyFile" },
    { "tunnel_hostkey", "TunnelHostKey" },
    { "tunnel_local_port", "TunnelLocalPortNumber" },
    { "auth_gssapi", "AuthGSSAPI" },
    { "auth_gssapi_kex", "AuthGSSAPIKEX" },
    { "gssapi_fwd_tgt", "GSSAPIFwdTGT" },
    { "logical_host", "LogicalHostName" },
    { "ftp_pasv_mode", "FtpPasvMode" },
    { "ftp_force_pasv_ip", "FtpForcePasvIp" },
    { "ftp_use_mlsd", "FtpUseMlsd" },
    { "ftp_account", "FtpAccount" },
    { "ftps", "Ftps" },
    { "min_tls_version", "MinTlsVersion" },
    { "max_tls_version", "MaxTlsVersion" },
    { "tls_certificate_file", "TlsCertificateFile" },
    { "tls_certificate_key_file", "TlsCertificateKeyFile" },
    { "ca_certificate_file", "CaCertificateFile" },
    { "ca_certificate_dir", "CaCertificateDir" },
    { "pinned_public_key", "PinnedPublicKey" },
    { "s3_storage_class", "S3StorageClass" },
    { "s3_acl", "S3Acl" },
    { "s3_sse", "S3ServerSideEncryption" },
    { "s3_kms_key_id", "S3KmsKeyId" },
    { "s3_request_payer", "S3RequestPayer" },
    { "s3_metadata", "S3Metadata" }
};

const char * SettingNameForSiteKey(const std::string & key)
{
    for (size_t i = 0; i < sizeof(kSiteSettingKeys) / sizeof(kSiteSettingKeys[0]); i++)
    {
        if (key == kSiteSettingKeys[i].key)
        {
            return kSiteSettingKeys[i].setting;
        }
    }
    return NULL;
}

std::string ValueOf(const StoredSession & session, const std::string & key,
    bool * isNumber)
{
    *isNumber = false;
    if (key == "protocol") { return session.protocol; }
    if (key == "host") { return session.hostName; }
    if (key == "username") { return session.userName; }
    if (key == "private_key") { return session.privateKeyFile; }
    if (key == "hostkey") { return session.hostKey; }
    if (key == "remote_directory") { return session.remoteDirectory; }
    if (key == "local_directory") { return session.localDirectory; }
    if (key == "preset") { return session.preset; }
    /* 'password' never comes through here: Save computes its encrypted
     * value before the file is opened (see the loop that writes). The
     * proxy password is written the same way, as 'proxy_password'. */
    if (key == "port")
    {
        *isNumber = true;
        return session.portNumber > 0 ? std::to_string(session.portNumber) : std::string();
    }
    /* The proxy keys are only written for a site that has a proxy at
     * all, so that a direct connection stores no proxy section. */
    if (session.proxy.Active())
    {
        if (key == "proxy_method")
        {
            return ProxyMethodName(session.proxy.method);
        }
        if (key == "proxy_host") { return session.proxy.host; }
        if (key == "proxy_username") { return session.proxy.userName; }
        if (key == "proxy_command") { return session.proxy.command; }
        if (key == "proxy_exclude") { return session.proxy.excludeList; }
        if (key == "proxy_port")
        {
            *isNumber = true;
            return session.proxy.port > 0 ?
                std::to_string(session.proxy.port) : std::string();
        }
        if (key == "proxy_dns")
        {
            *isNumber = true;
            return std::to_string(session.proxy.dns);
        }
        if (key == "proxy_localhost")
        {
            *isNumber = true;
            return std::string(session.proxy.evenLocalhost ? "1" : "0");
        }
    }
    if (session.tunnel.enabled)
    {
        if (key == "tunnel") { return "1"; }
        if (key == "tunnel_host") { return session.tunnel.hostName; }
        if (key == "tunnel_port") { return std::to_string(session.tunnel.portNumber); }
        if (key == "tunnel_username") { return session.tunnel.userName; }
        if (key == "tunnel_private_key") { return session.tunnel.privateKeyFile; }
        if (key == "tunnel_hostkey") { return session.tunnel.hostKey; }
        if (key == "tunnel_local_port")
        {
            *isNumber = true;
            return session.tunnel.localPortNumber > 0 ?
                std::to_string(session.tunnel.localPortNumber) :
                std::string();
        }
    }
    /* GSSAPI policy: written only where it differs from upstream's
     * defaults (mic on, key exchange and delegation off). */
    if (key == "auth_gssapi")
    {
        return session.gssapi.auth ? std::string() : std::string("0");
    }
    if (key == "auth_gssapi_kex")
    {
        return session.gssapi.authKex ? std::string("1") : std::string();
    }
    if (key == "gssapi_fwd_tgt")
    {
        return session.gssapi.forwardTgt ? std::string("1") : std::string();
    }
    if (key == "logical_host") { return session.gssapi.logicalHost; }
    /* The FTP/TLS settings of the site: written only when they differ
     * from what a connection would use without them. */
    if (key == "ftp_pasv_mode")
    {
        return session.ftp.passiveMode ? std::string() : std::string("0");
    }
    if (key == "ftp_force_pasv_ip")
    {
        return session.ftp.forcePasvIp != 1 ?
            std::to_string(session.ftp.forcePasvIp) : std::string();
    }
    if (key == "ftp_use_mlsd")
    {
        return session.ftp.useMlsd != 1 ?
            std::to_string(session.ftp.useMlsd) : std::string();
    }
    if (key == "ftp_account") { return session.ftp.account; }
    if (key == "ftps")
    {
        return session.tls.ftpsMode != 0 ?
            std::to_string(session.tls.ftpsMode) : std::string();
    }
    if (key == "min_tls_version")
    {
        return session.tls.minVersion != 0 ?
            std::to_string(session.tls.minVersion) : std::string();
    }
    if (key == "max_tls_version")
    {
        return session.tls.maxVersion != 0 ?
            std::to_string(session.tls.maxVersion) : std::string();
    }
    if (key == "tls_certificate_file") { return session.tls.clientCertificate; }
    if (key == "tls_certificate_key_file") { return session.tls.clientKey; }
    if (key == "ca_certificate_file") { return session.tls.caFile; }
    if (key == "ca_certificate_dir") { return session.tls.caDirectory; }
    if (key == "pinned_public_key") { return session.tls.pinnedPublicKey; }
    if (key == "s3_storage_class") { return session.s3.storageClass; }
    if (key == "s3_acl") { return session.s3.acl; }
    if (key == "s3_sse") { return session.s3.serverSideEncryption; }
    if (key == "s3_kms_key_id") { return session.s3.kmsKeyId; }
    if (key == "s3_request_payer")
    {
        return session.s3.requestPayer ? std::string("1") : std::string();
    }
    if (key == "s3_metadata")
    {
        std::string out;
        for (std::map<std::string, std::string>::const_iterator it =
                session.s3.metadata.begin();
             it != session.s3.metadata.end(); ++it)
        {
            if (!out.empty())
            {
                out += ",";
            }
            out += it->first + "=" + it->second;
        }
        return out;
    }
    if (key == "last_used")
    {
        *isNumber = true;
        return session.lastUsed != 0 ? std::to_string(session.lastUsed) : std::string();
    }
    return std::string();
}

/* The key file that pairs with an ini path: 'sessions.ini' becomes
 * 'sessions.key', anything else gains '.key'. */
std::string KeyPathFor(const std::string & iniPath)
{
    if (iniPath.empty())
    {
        return std::string();
    }
    if (iniPath.size() >= 4 &&
        iniPath.compare(iniPath.size() - 4, 4, ".ini") == 0)
    {
        return iniPath.substr(0, iniPath.size() - 4) + ".key";
    }
    return iniPath + ".key";
}

/* ---- the password format ------------------------------------------------ */

const char b64Digits[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const std::string & data)
{
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    size_t i = 0;
    while (i + 3 <= data.size())
    {
        const unsigned int group =
            (static_cast<unsigned char>(data[i]) << 16) |
            (static_cast<unsigned char>(data[i + 1]) << 8) |
            static_cast<unsigned char>(data[i + 2]);
        out += b64Digits[(group >> 18) & 63];
        out += b64Digits[(group >> 12) & 63];
        out += b64Digits[(group >> 6) & 63];
        out += b64Digits[group & 63];
        i += 3;
    }
    if (i < data.size())
    {
        unsigned int group = static_cast<unsigned char>(data[i]) << 16;
        if (i + 1 < data.size())
        {
            group |= static_cast<unsigned char>(data[i + 1]) << 8;
        }
        out += b64Digits[(group >> 18) & 63];
        out += b64Digits[(group >> 12) & 63];
        out += i + 1 < data.size() ? b64Digits[(group >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

bool Base64Decode(const std::string & text, std::string & data)
{
    data.clear();
    if (text.size() % 4 != 0)
    {
        return false;
    }
    unsigned int val = 0;
    int valb = -8;
    for (size_t i = 0; i < text.size(); i++)
    {
        const char c = text[i];
        if (c == '=')
        {
            continue; /* padding: the bits it carries are zero anyway */
        }
        const char * found = strchr(b64Digits, c);
        if (found == NULL || c == '\0')
        {
            return false;
        }
        /* Unsigned, and kept to the bits that have not been emitted yet:
         * a signed accumulator overflowed on the fifth character of any
         * input longer than a few bytes, which is undefined behaviour
         * rather than more decoded data. */
        val = ((val << 6) |
            static_cast<unsigned int>(found - b64Digits)) & 0xFFFu;
        valb += 6;
        if (valb >= 0)
        {
            data += static_cast<char>((val >> valb) & 0xFFu);
            valb -= 8;
        }
    }
    return true;
}

bool RandomBytes(void * buffer, size_t length)
{
    FILE * file = fopen("/dev/urandom", "rb");
    if (file == NULL)
    {
        return false;
    }
    const size_t got = fread(buffer, 1, length, file);
    fclose(file);
    return got == length;
}

void DeriveKeys(const std::string & master, unsigned char * encKey,
    unsigned char * macKey)
{
    lscp_hmac_sha256(master.data(), master.size(),
        kEncKeyLabel, strlen(kEncKeyLabel), encKey, kKeyBytes);
    lscp_hmac_sha256(master.data(), master.size(),
        kMacKeyLabel, strlen(kMacKeyLabel), macKey, kKeyBytes);
}

void BurnKey(unsigned char * key, size_t length)
{
    volatile unsigned char * p = key;
    while (length-- > 0)
    {
        *p++ = 0;
    }
}

void HmacSha256(const unsigned char * key, size_t keyLength,
    const void * data, size_t dataLength, unsigned char * out)
{
    lscp_hmac_sha256(key, keyLength, data, dataLength, out, kKeyBytes);
}

bool TagsEqual(const unsigned char * a, const unsigned char * b)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < kTagBytes; i++)
    {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/* One keystream block: HMAC-SHA256(encKey, nonce || block counter,
 * big endian). */
void KeystreamBlock(const unsigned char * encKey, const unsigned char * nonce,
    unsigned int counter, unsigned char * out)
{
    unsigned char input[kNonceBytes + 4];
    memcpy(input, nonce, kNonceBytes);
    input[kNonceBytes + 0] = static_cast<unsigned char>(counter >> 24);
    input[kNonceBytes + 1] = static_cast<unsigned char>(counter >> 16);
    input[kNonceBytes + 2] = static_cast<unsigned char>(counter >> 8);
    input[kNonceBytes + 3] = static_cast<unsigned char>(counter);
    HmacSha256(encKey, kKeyBytes, input, sizeof(input), out);
}

/* ---- the key file ------------------------------------------------------- */

enum KeyReadResult { KeyReadOk = 0, KeyReadMissing = -1, KeyReadInvalid = 1 };

/* Reads the key file: 0 with 'key' holding 32 raw bytes, -1 when it
 * does not exist ('error' untouched), 1 when it exists but cannot be
 * used ('error' says why). Both a raw 32-byte file and its base64
 * spelling are accepted, so a hand-made key works. */
KeyReadResult ReadKeyFile(const std::string & path, std::string & key,
    std::string & error)
{
    if (path.empty())
    {
        error = "There is no configuration directory to keep a key file in "
            "(set HOME, or LINSCP_CONFIG_DIR to choose one).";
        return KeyReadInvalid;
    }
    FILE * file = fopen(path.c_str(), "rb");
    if (file == NULL)
    {
        return KeyReadMissing;
    }
    std::string content;
    char buffer[512];
    size_t got;
    while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0 &&
        content.size() <= 1024 * 1024)
    {
        content.append(buffer, got);
    }
    const bool readFailed = ferror(file) != 0;
    fclose(file);
    if (readFailed)
    {
        error = "The encryption key file '" + path + "' cannot be read.";
        return KeyReadInvalid;
    }
    const std::string trimmed = Trim(content);
    if (trimmed.size() == kKeyBytes)
    {
        key = trimmed;
        return KeyReadOk;
    }
    std::string decoded;
    if (trimmed.size() >= 4 && trimmed.size() % 4 == 0 &&
        Base64Decode(trimmed, decoded) && decoded.size() == kKeyBytes)
    {
        key = decoded;
        return KeyReadOk;
    }
    error = "The encryption key file '" + path +
        "' does not contain a 32-byte key (base64 or raw); " +
        "remove it to have a new one created, or restore it from a copy.";
    return KeyReadInvalid;
}

/* Writes 'content' to a file that must not exist yet. Returns 0 when
 * created, 1 when somebody else created it first, -1 on failure. */
int CreateKeyFileExclusive(const std::string & path,
    const std::string & content, std::string & error)
{
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
    {
        return errno == EEXIST ? 1 : -1;
    }
    size_t offset = 0;
    while (offset < content.size())
    {
        const ssize_t n = write(fd, content.data() + offset,
            content.size() - offset);
        if (n <= 0)
        {
            close(fd);
            unlink(path.c_str());
            error = "The encryption key file '" + path + "' cannot be written.";
            return -1;
        }
        offset += static_cast<size_t>(n);
    }
    close(fd);
    RestrictFileToUser(path);
    return 0;
}

/* The key for encrypting: read it, or create it with fresh randomness.
 * Only Save() creates - Load() must never grow files on its own. */
bool LoadOrCreateKeyFile(const std::string & path, std::string & key,
    std::string & error)
{
    const KeyReadResult read = ReadKeyFile(path, key, error);
    if (read == KeyReadOk)
    {
        return true;
    }
    if (read == KeyReadInvalid)
    {
        return false;
    }

    unsigned char raw[kKeyBytes];
    if (!RandomBytes(raw, sizeof(raw)))
    {
        error = "No source of random bytes is available to create the "
            "encryption key file.";
        return false;
    }
    const std::string content = Base64Encode(
        std::string(reinterpret_cast<const char *>(raw), sizeof(raw))) + "\n";
    BurnKey(raw, sizeof(raw));

    const int created = CreateKeyFileExclusive(path, content, error);
    if (created == 0)
    {
        const KeyReadResult again = ReadKeyFile(path, key, error);
        return again == KeyReadOk;
    }
    if (created > 0)
    {
        /* Another process won the race; its key is the one to use. */
        return ReadKeyFile(path, key, error) == KeyReadOk;
    }
    if (error.empty())
    {
        error = "The encryption key file '" + path + "' cannot be created.";
    }
    return false;
}

} // namespace

bool SessionStore::EncryptPassword(const std::string & plain,
    const std::string & key, std::string & encoded, std::string & error)
{
    error.clear();
    encoded.clear();
    if (key.size() != kKeyBytes)
    {
        error = "The encryption key must be 32 bytes.";
        return false;
    }
    if (plain.size() > kMaxPasswordBytes)
    {
        error = "The password is too long to store.";
        return false;
    }

    unsigned char encKey[kKeyBytes];
    unsigned char macKey[kKeyBytes];
    DeriveKeys(key, encKey, macKey);

    unsigned char nonce[kNonceBytes];
    if (!RandomBytes(nonce, sizeof(nonce)))
    {
        BurnKey(encKey, sizeof(encKey));
        BurnKey(macKey, sizeof(macKey));
        error = "No source of random bytes is available to encrypt the "
            "password.";
        return false;
    }

    std::string cipher(plain.size(), '\0');
    unsigned char block[kKeyBytes];
    unsigned int counter = 0;
    size_t done = 0;
    while (done < plain.size())
    {
        KeystreamBlock(encKey, nonce, counter, block);
        const size_t take = plain.size() - done < sizeof(block) ?
            plain.size() - done : sizeof(block);
        for (size_t i = 0; i < take; i++)
        {
            cipher[done + i] = static_cast<char>(
                static_cast<unsigned char>(plain[done + i]) ^ block[i]);
        }
        done += take;
        counter++;
    }

    const std::string tagInput = std::string(kTagLabel) +
        std::string(reinterpret_cast<const char *>(nonce), sizeof(nonce)) +
        cipher;
    unsigned char tag[kTagBytes];
    HmacSha256(macKey, sizeof(macKey), tagInput.data(), tagInput.size(), tag);

    const std::string blob =
        std::string(reinterpret_cast<const char *>(nonce), sizeof(nonce)) +
        cipher +
        std::string(reinterpret_cast<const char *>(tag), sizeof(tag));
    encoded = std::string(kPasswordPrefix) + Base64Encode(blob);

    BurnKey(encKey, sizeof(encKey));
    BurnKey(macKey, sizeof(macKey));
    return true;
}

bool SessionStore::DecryptPassword(const std::string & encoded,
    const std::string & key, std::string & plain, std::string & error)
{
    error.clear();
    plain.clear();
    if (key.size() != kKeyBytes)
    {
        error = "The encryption key must be 32 bytes.";
        return false;
    }
    if (!StartsWith(encoded, kPasswordPrefix))
    {
        error = "The stored password is not encrypted with a known format.";
        return false;
    }
    std::string blob;
    const std::string body = encoded.substr(strlen(kPasswordPrefix));
    if (!Base64Decode(body, blob) ||
        blob.size() < kNonceBytes + kTagBytes ||
        blob.size() - kNonceBytes - kTagBytes > kMaxPasswordBytes)
    {
        error = "The stored password is corrupted: its encoding is not "
            "valid base64 of the expected shape.";
        return false;
    }

    const unsigned char * nonce =
        reinterpret_cast<const unsigned char *>(blob.data());
    const size_t cipherLength = blob.size() - kNonceBytes - kTagBytes;
    const std::string cipher = blob.substr(kNonceBytes, cipherLength);
    const unsigned char * tag = reinterpret_cast<const unsigned char *>(
        blob.data() + kNonceBytes + cipherLength);

    const std::string tagInput = std::string(kTagLabel) +
        blob.substr(0, kNonceBytes) + cipher;
    unsigned char encKey[kKeyBytes];
    unsigned char macKey[kKeyBytes];
    DeriveKeys(key, encKey, macKey);
    unsigned char expected[kTagBytes];
    HmacSha256(macKey, sizeof(macKey), tagInput.data(), tagInput.size(),
        expected);
    BurnKey(macKey, sizeof(macKey));

    if (!TagsEqual(expected, tag))
    {
        BurnKey(encKey, sizeof(encKey));
        error = "The stored password does not match this key file: it was "
            "encrypted somewhere else, or the value was modified.";
        return false;
    }

    plain.resize(cipherLength);
    unsigned char block[kKeyBytes];
    unsigned int counter = 0;
    size_t done = 0;
    while (done < cipherLength)
    {
        KeystreamBlock(encKey, nonce, counter, block);
        const size_t take = cipherLength - done < sizeof(block) ?
            cipherLength - done : sizeof(block);
        for (size_t i = 0; i < take; i++)
        {
            plain[done + i] = static_cast<char>(
                static_cast<unsigned char>(cipher[done + i]) ^ block[i]);
        }
        done += take;
        counter++;
    }
    BurnKey(encKey, sizeof(encKey));
    return true;
}

SessionStore::SessionStore() : mPath(DefaultPath())
{
    mKeyPath = KeyPathFor(mPath);
    std::string error;
    Load(error);
}

SessionStore::SessionStore(const std::string & path) : mPath(path)
{
    mKeyPath = KeyPathFor(mPath);
    std::string error;
    Load(error);
}

std::string SessionStore::DefaultPath()
{
    const std::string config = ConfigDirectory();
    if (config.empty())
    {
        return std::string();
    }
    return config + "/sessions.ini";
}

bool SessionStore::IsValidName(const std::string & name)
{
    if (name.empty() || name.size() > 512)
    {
        return false;
    }
    if (name.find_first_not_of(" \t") == std::string::npos)
    {
        return false;
    }
    if (name[0] == ' ' || name[0] == '\t' ||
        name[name.size() - 1] == ' ' || name[name.size() - 1] == '\t' ||
        name[0] == '/' || name[name.size() - 1] == '/')
    {
        return false;
    }
    if (name.find("//") != std::string::npos)
    {
        return false;
    }
    for (size_t i = 0; i < name.size(); i++)
    {
        if (static_cast<unsigned char>(name[i]) < 0x20 || name[i] == ']')
        {
            return false;
        }
    }
    return true;
}

const StoredSession * SessionStore::Find(const std::string & name) const
{
    if (name.empty())
    {
        return NULL;
    }
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        if (mSessions[i].name == name)
        {
            return &mSessions[i];
        }
    }
    const std::string wanted = Lower(Trim(name));
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        if (Lower(mSessions[i].name) == wanted)
        {
            return &mSessions[i];
        }
    }
    /* A bare host name is a reasonable way to name a session, so let
     * 'open web.example.com' find the session of that host. */
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        if (Lower(mSessions[i].hostName) == wanted)
        {
            return &mSessions[i];
        }
    }
    return NULL;
}

bool SessionStore::AddOrUpdate(const StoredSession & session, std::string & error)
{
    if (!IsValidName(session.name))
    {
        error = "The session name '" + session.name + "' is not valid.";
        return false;
    }
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        if (Lower(mSessions[i].name) == Lower(session.name))
        {
            mSessions[i] = session;
            return true;
        }
    }
    mSessions.push_back(session);
    return true;
}

bool SessionStore::Remove(const std::string & name, std::string & error)
{
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        if (Lower(mSessions[i].name) == Lower(name))
        {
            mSessions.erase(mSessions.begin() + static_cast<long>(i));
            return true;
        }
    }
    error = "There is no stored session named '" + name + "'.";
    return false;
}

bool SessionStore::Rename(const std::string & from, const std::string & to,
    std::string & error)
{
    if (!IsValidName(to))
    {
        error = "The session name '" + to + "' is not valid.";
        return false;
    }
    const StoredSession * existing = Find(from);
    if (existing == NULL)
    {
        error = "There is no stored session named '" + from + "'.";
        return false;
    }
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        if (&mSessions[i] == existing)
        {
            mSessions[i].name = to;
            return true;
        }
    }
    error = "There is no stored session named '" + from + "'.";
    return false;
}

std::vector<std::string> SessionStore::Folders() const
{
    std::vector<std::string> folders;
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        const std::string & name = mSessions[i].name;
        size_t pos = 0;
        while ((pos = name.find('/', pos)) != std::string::npos)
        {
            const std::string folder = name.substr(0, pos);
            bool seen = false;
            for (size_t k = 0; k < folders.size(); k++)
            {
                if (Lower(folders[k]) == Lower(folder))
                {
                    seen = true;
                    break;
                }
            }
            if (!seen)
            {
                folders.push_back(folder);
            }
            pos++;
        }
    }
    return folders;
}

std::vector<StoredSession> SessionStore::SessionsInFolder(
    const std::string & folder) const
{
    std::string prefix = Trim(folder);
    while (!prefix.empty() && prefix[prefix.size() - 1] == '/')
    {
        prefix.erase(prefix.size() - 1);
    }
    std::vector<StoredSession> out;
    if (prefix.empty())
    {
        return mSessions;
    }
    const std::string wanted = Lower(prefix) + "/";
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        if (StartsWith(Lower(mSessions[i].name), wanted.c_str()))
        {
            out.push_back(mSessions[i]);
        }
    }
    return out;
}

int SessionStore::RemoveFolder(const std::string & folder, std::string & error)
{
    error.clear();
    std::string prefix = Trim(folder);
    while (!prefix.empty() && prefix[prefix.size() - 1] == '/')
    {
        prefix.erase(prefix.size() - 1);
    }
    if (prefix.empty())
    {
        error = "No session folder name was given.";
        return 0;
    }
    const std::string wanted = Lower(prefix) + "/";
    int removed = 0;
    for (size_t i = mSessions.size(); i > 0; i--)
    {
        if (StartsWith(Lower(mSessions[i - 1].name), wanted.c_str()))
        {
            mSessions.erase(mSessions.begin() + static_cast<long>(i - 1));
            removed++;
        }
    }
    if (removed == 0)
    {
        error = "There are no stored sessions in folder '" + prefix + "'.";
    }
    return removed;
}

bool SessionStore::Load(std::string & error)
{
    error.clear();
    mSessions.clear();
    if (mPath.empty())
    {
        return true;
    }
    FILE * file = fopen(mPath.c_str(), "rb");
    if (file == NULL)
    {
        return true; /* no stored sessions yet */
    }

    /* The key file is read at most once per load, and only when the
     * file actually holds an encrypted password. */
    bool keyTried = false;
    bool keyOk = false;
    std::string keyBytes;
    std::string keyError;

    StoredSession current;
    bool inSection = false;
    char buffer[8192];
    while (fgets(buffer, sizeof(buffer), file) != NULL)
    {
        std::string line(buffer);
        while (!line.empty() && (line[line.size() - 1] == '\n' || line[line.size() - 1] == '\r'))
        {
            line.erase(line.size() - 1);
        }
        const std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';')
        {
            continue;
        }
        if (trimmed[0] == '[' && trimmed[trimmed.size() - 1] == ']')
        {
            if (inSection)
            {
                mSessions.push_back(current);
            }
            current = StoredSession();
            current.name = UnescapeValue(trimmed.substr(1, trimmed.size() - 2));
            inSection = true;
            continue;
        }
        const size_t equals = trimmed.find('=');
        if (equals == std::string::npos)
        {
            continue; /* not a line this format understands: ignore it */
        }
        if (!inSection)
        {
            continue; /* a value outside any section */
        }
        const std::string key = Lower(Trim(trimmed.substr(0, equals)));
        const std::string value = UnescapeValue(Trim(trimmed.substr(equals + 1)));
        if (key == "port")
        {
            /* A stored port is a number the file states, not one the user
             * typed at a prompt that validates it: atoi() turned text
             * into 0 and had undefined behaviour on overflow, so a file
             * edited by hand could store a port nothing connects with.
             * Out of range stays the previous value, which 'open' then
             * reports the way it reports any unusable stored site. */
            char * end = NULL;
            const long port = strtol(value.c_str(), &end, 10);
            if (end != NULL && *end == '\0' && port >= 1 && port <= 65535)
            {
                current.portNumber = static_cast<int>(port);
            }
        }
        else if (key == "last_used")
        {
            current.lastUsed = strtoull(value.c_str(), NULL, 10);
        }
        else if (key == "protocol") { current.protocol = value; }
        else if (key == "host" || key == "hostname") { current.hostName = value; }
        else if (key == "username" || key == "user") { current.userName = value; }
        else if (key == "private_key" || key == "privatekey" || key == "keyfile")
        {
            current.privateKeyFile = value;
        }
        else if (key == "hostkey" || key == "host_key") { current.hostKey = value; }
        else if (key == "remote_directory" || key == "remotedir")
        {
            current.remoteDirectory = value;
        }
        else if (key == "local_directory" || key == "localdir")
        {
            current.localDirectory = value;
        }
        else if (key == "preset")
        {
            current.preset = value;
        }
        else if (SettingNameForSiteKey(key) != NULL)
        {
            /* One parser for both doors: a stored setting and a
             * '-rawsettings' one mean the same thing, and a value the
             * parser refuses is reported the same way. */
            SessionOptions scratch;
            scratch.ftp = current.ftp;
            scratch.tls = current.tls;
            scratch.s3 = current.s3;
            scratch.tunnel = current.tunnel;
            scratch.gssapi = current.gssapi;
            std::string settingError;
            if (ApplySessionRawSetting(SettingNameForSiteKey(key), value,
                scratch, settingError))
            {
                current.ftp = scratch.ftp;
                current.tls = scratch.tls;
                current.s3 = scratch.s3;
                current.tunnel = scratch.tunnel;
                current.gssapi = scratch.gssapi;
            }
            else if (current.settingError.empty())
            {
                current.settingError = "the stored setting '" + key +
                    "' cannot be used: " + settingError;
            }
        }
        else if (key == "proxy_method")
        {
            ProxyMethod method = ProxyMethod::None;
            if (ParseProxyMethod(value, method))
            {
                current.proxy.method = method;
            }
            else if (current.proxyError.empty())
            {
                current.proxyError = "the stored proxy method '" + value +
                    "' is not one this build knows";
            }
        }
        else if (key == "proxy_host") { current.proxy.host = value; }
        else if (key == "proxy_username") { current.proxy.userName = value; }
        else if (key == "proxy_command") { current.proxy.command = value; }
        else if (key == "proxy_exclude") { current.proxy.excludeList = value; }
        else if (key == "proxy_port")
        {
            char * end = NULL;
            const long port = strtol(value.c_str(), &end, 10);
            if (end != NULL && *end == '\0' && port > 0 && port <= 65535)
            {
                current.proxy.port = static_cast<int>(port);
            }
        }
        else if (key == "proxy_dns")
        {
            char * end = NULL;
            const long dns = strtol(value.c_str(), &end, 10);
            if (end != NULL && *end == '\0' && dns >= 0 && dns <= 2)
            {
                current.proxy.dns = static_cast<int>(dns);
            }
        }
        else if (key == "proxy_localhost")
        {
            current.proxy.evenLocalhost = value == "1" || Lower(value) == "on" ||
                Lower(value) == "true";
        }
        else if (key == "proxy_password" || key == "tunnel_password" ||
                 key == "tunnel_passphrase")
        {
            std::string & plain = key == "proxy_password" ? current.proxy.password :
                (key == "tunnel_password" ? current.tunnel.password : current.tunnel.keyPassphrase);
            std::string & raw = key == "proxy_password" ? current.proxyPasswordRaw :
                (key == "tunnel_password" ? current.tunnelPasswordRaw : current.tunnelPassphraseRaw);
            std::string & credentialError = key == "proxy_password" ? current.proxyError : current.tunnelError;
            if (!StartsWith(value, kPasswordPrefix))
            {
                // Migrate legacy plaintext on the next save, just like the site password.
                plain = value;
            }
            else
            {
                raw = value;
                if (!keyTried)
                {
                    keyTried = true;
                    const KeyReadResult read = ReadKeyFile(mKeyPath, keyBytes, keyError);
                    keyOk = read == KeyReadOk;
                    if (read == KeyReadMissing)
                        keyError = "the encryption key file '" + mKeyPath +
                            "' does not exist; restore it or store the credential again";
                }
                std::string decryptError;
                if (!keyOk)
                {
                    credentialError = keyError;
                }
                else if (!DecryptPassword(value, keyBytes, plain, decryptError))
                {
                    credentialError = decryptError;
                }
                else if (plain.empty())
                {
                    credentialError = "the stored credential in '" + key + "' is empty";
                }
                else
                {
                    raw.clear();
                }
            }
        }
        else if (key == "password")
        {
            if (StartsWith(value, kPasswordPrefix))
            {
                current.passwordStored = true;
                current.passwordRaw = value;
                if (!keyTried)
                {
                    keyTried = true;
                    const KeyReadResult read =
                        ReadKeyFile(mKeyPath, keyBytes, keyError);
                    keyOk = read == KeyReadOk;
                    if (read == KeyReadInvalid)
                    {
                        /* keyError explains the file itself. */
                    }
                    else if (read == KeyReadMissing)
                    {
                        keyError = "the encryption key file '" + mKeyPath +
                            "' does not exist (it is created when the first "
                            "password is stored); restore it from a copy or "
                            "store the password again";
                    }
                }
                if (!keyOk)
                {
                    current.passwordError = keyError;
                }
                else if (!DecryptPassword(value, keyBytes, current.password,
                             current.passwordError))
                {
                    current.password.clear();
                }
                else if (current.password.empty())
                {
                    current.passwordError =
                        "the stored password in the file is empty";
                }
                else
                {
                    current.passwordRaw.clear();
                }
            }
            else
            {
                /* Plaintext from before the encryption existed; the
                 * next Save() rewrites it encrypted. */
                current.password = value;
                current.passwordStored = !value.empty();
            }
        }
    }
    if (inSection)
    {
        mSessions.push_back(current);
    }
    fclose(file);

    std::sort(mSessions.begin(), mSessions.end(),
        [](const StoredSession & left, const StoredSession & right)
        {
            return Lower(left.name) < Lower(right.name);
        });
    return true;
}

bool SessionStore::Save(std::string & error) const
{
    error.clear();
    if (mPath.empty())
    {
        error = "There is no configuration directory, so the session cannot "
            "be stored (set HOME, or LINSCP_CONFIG_DIR to choose one).";
        return false;
    }

    std::vector<StoredSession> sorted = mSessions;
    std::sort(sorted.begin(), sorted.end(),
        [](const StoredSession & left, const StoredSession & right)
        {
            return Lower(left.name) < Lower(right.name);
        });

    /*
     * Every password value is resolved before the file is opened: a
     * usable password is encrypted under the key file (creating it on
     * first use), a password that could not be decrypted is written
     * back verbatim so that a save never destroys what it cannot read.
     * If any of that fails, the previous file is left untouched.
     */
    /*
     * The directory has to exist before anything is created inside it -
     * the key file included - so it comes first.
     */
    const size_t slash = mPath.find_last_of('/');
    if (slash != std::string::npos && slash > 0)
    {
        const std::string directory = mPath.substr(0, slash);
        std::string createError;
        if (!CreatePrivateDirectory(directory, createError))
        {
            error = createError;
            return false;
        }
    }

    std::vector<std::string> passwordValues(sorted.size());
    std::vector<bool> hasPasswordValue(sorted.size(), false);
    /* The proxy password is a password too: it is encrypted under the same
     * key file, and a ciphertext this machine cannot read is written back
     * unchanged rather than dropped. */
    std::vector<std::string> proxyPasswordValues(sorted.size());
    std::vector<bool> hasProxyPasswordValue(sorted.size(), false);
    std::vector<std::string> tunnelPasswordValues(sorted.size());
    std::vector<std::string> tunnelPassphraseValues(sorted.size());
    bool anyPassword = false;
    for (size_t i = 0; i < sorted.size(); i++)
    {
        if (!sorted[i].password.empty())
        {
            std::string key;
            if (!LoadOrCreateKeyFile(mKeyPath, key, error))
            {
                return false;
            }
            std::string encoded;
            const bool ok = EncryptPassword(sorted[i].password, key, encoded,
                error);
            BurnKey(
                reinterpret_cast<unsigned char *>(&key[0]), key.size());
            if (!ok)
            {
                error = "Cannot encrypt the stored password of '" +
                    sorted[i].name + "': " + error;
                return false;
            }
            passwordValues[i] = encoded;
            hasPasswordValue[i] = true;
            anyPassword = true;
        }
        else if (sorted[i].passwordStored && !sorted[i].passwordRaw.empty())
        {
            passwordValues[i] = sorted[i].passwordRaw;
            hasPasswordValue[i] = true;
            anyPassword = true;
        }

        if (!sorted[i].proxy.password.empty())
        {
            std::string key;
            if (!LoadOrCreateKeyFile(mKeyPath, key, error))
            {
                return false;
            }
            std::string encoded;
            const bool ok = EncryptPassword(sorted[i].proxy.password, key,
                encoded, error);
            BurnKey(
                reinterpret_cast<unsigned char *>(&key[0]), key.size());
            if (!ok)
            {
                error = "Cannot encrypt the stored proxy password of '" +
                    sorted[i].name + "': " + error;
                return false;
            }
            proxyPasswordValues[i] = encoded;
            hasProxyPasswordValue[i] = true;
            anyPassword = true;
        }
        else if (!sorted[i].proxyPasswordRaw.empty())
        {
            proxyPasswordValues[i] = sorted[i].proxyPasswordRaw;
            hasProxyPasswordValue[i] = true;
            anyPassword = true;
        }
        if (sorted[i].tunnel.enabled)
        {
            for (int secret = 0; secret < 2; ++secret)
            {
                const std::string & plain = secret == 0 ?
                    sorted[i].tunnel.password : sorted[i].tunnel.keyPassphrase;
                const std::string & raw = secret == 0 ?
                    sorted[i].tunnelPasswordRaw : sorted[i].tunnelPassphraseRaw;
                std::string & encoded = secret == 0 ?
                    tunnelPasswordValues[i] : tunnelPassphraseValues[i];
                if (!plain.empty())
                {
                    std::string key;
                    if (!LoadOrCreateKeyFile(mKeyPath, key, error)) return false;
                    const bool ok = EncryptPassword(plain, key, encoded, error);
                    BurnKey(reinterpret_cast<unsigned char *>(&key[0]), key.size());
                    if (!ok) return false;
                }
                else encoded = raw;
                anyPassword = anyPassword || !encoded.empty();
            }
        }
    }

    FILE * file = fopen(mPath.c_str(), "wb");
    if (file == NULL)
    {
        error = std::string("Cannot write the session file '") + mPath + "'.";
        return false;
    }
    fprintf(file, "# LinSCP stored sessions. Names may contain '/' to group\n");
    fprintf(file, "# sessions into folders. Passwords are only stored when\n");
    fprintf(file, "# they are saved explicitly, encrypted under sessions.key.\n");
    for (size_t i = 0; i < sorted.size(); i++)
    {
        fprintf(file, "\n[%s]\n", EscapeValue(sorted[i].name).c_str());
        static const char * const keys[] = {
            "protocol", "host", "port", "username", "private_key", "hostkey",
            "remote_directory", "local_directory", "password", "last_used",
            "preset", "proxy_method", "proxy_host", "proxy_port",
            "proxy_username", "proxy_password", "proxy_command",
            "proxy_exclude", "proxy_dns", "proxy_localhost",
            "ftp_pasv_mode", "ftp_force_pasv_ip", "ftp_use_mlsd",
            "ftp_account", "ftps", "min_tls_version", "max_tls_version",
            "tls_certificate_file", "tls_certificate_key_file",
            "ca_certificate_file", "ca_certificate_dir", "pinned_public_key",
            "s3_storage_class", "s3_acl", "s3_sse", "s3_kms_key_id",
            "s3_request_payer", "s3_metadata", "tunnel", "tunnel_host",
            "tunnel_port", "tunnel_username", "tunnel_private_key",
            "tunnel_hostkey", "tunnel_password", "tunnel_passphrase",
            "tunnel_local_port", "auth_gssapi", "auth_gssapi_kex",
            "gssapi_fwd_tgt", "logical_host"
        };
        for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
        {
            bool isNumber = false;
            std::string value;
            if (strcmp(keys[k], "password") == 0)
            {
                if (!hasPasswordValue[i])
                {
                    continue;
                }
                value = passwordValues[i];
            }
            else if (strcmp(keys[k], "proxy_password") == 0)
            {
                /* A site that no longer has a proxy stores no credential
                 * for one: 'ProxyMethod=None' has to take the encrypted
                 * value with it, not leave a secret behind that nothing
                 * uses. */
                if (!hasProxyPasswordValue[i] || !sorted[i].proxy.Active())
                {
                    continue;
                }
                value = proxyPasswordValues[i];
            }
            else if (strcmp(keys[k], "tunnel_password") == 0 ||
                     strcmp(keys[k], "tunnel_passphrase") == 0)
            {
                value = strcmp(keys[k], "tunnel_password") == 0 ?
                    tunnelPasswordValues[i] : tunnelPassphraseValues[i];
                if (value.empty()) continue;
            }
            else
            {
                value = ValueOf(sorted[i], keys[k], &isNumber);
                if (value.empty())
                {
                    continue;
                }
            }
            fprintf(file, "%s=%s\n", keys[k], EscapeValue(value).c_str());
            (void)isNumber;
        }
    }
    fclose(file);
    if (anyPassword)
    {
        RestrictFileToUser(mPath);
    }
    return true;
}

int SessionStore::ImportFile(const std::string & path, bool merge, std::string & error)
{
    SessionStore imported(path);
    int count = 0;
    for (size_t i = 0; i < imported.Sessions().size(); i++)
    {
        const StoredSession & session = imported.Sessions()[i];
        bool replaced = false;
        for (size_t k = 0; k < mSessions.size(); k++)
        {
            if (Lower(mSessions[k].name) == Lower(session.name))
            {
                if (!merge)
                {
                    mSessions[k] = session;
                }
                replaced = true;
                break;
            }
        }
        if (!replaced)
        {
            mSessions.push_back(session);
        }
        count++;
    }
    (void)error;
    return count;
}

bool SessionStore::ExportFile(const std::string & path, std::string & error)
{
    SessionStore copy(path);
    for (size_t i = 0; i < mSessions.size(); i++)
    {
        std::string addError;
        if (!copy.AddOrUpdate(mSessions[i], addError))
        {
            error = addError;
            return false;
        }
    }
    return copy.Save(error);
}

SessionOptions SessionStore::ToSessionOptions(const StoredSession & session,
    const SessionOptions & defaults)
{
    SessionOptions options = defaults;
    if (!session.protocol.empty())
    {
        options.protocol = session.protocol;
    }
    if (!session.hostName.empty())
    {
        options.hostName = session.hostName;
    }
    if (session.portNumber > 0)
    {
        options.portNumber = session.portNumber;
        /* Earlier versions of 'savesession' and of the graphical client
         * wrote the SSH port for every site nobody gave a port for, so a
         * file may still hold 'port=22' on an FTP, WebDAV or S3 site. That
         * value is the default they failed to replace, not a choice, and
         * it is read as the port of the protocol - the same rule 'open
         * ftp://host' applies to a URL without a port. */
        const int protocolDefault = SessionDefaultPort(options.protocol,
            session.tls.ftpsMode);
        if (session.portNumber == 22 && protocolDefault != 22)
        {
            options.portNumber = protocolDefault;
        }
    }
    if (!session.userName.empty())
    {
        options.userName = session.userName;
    }
    if (!session.privateKeyFile.empty())
    {
        options.privateKeyFile = session.privateKeyFile;
    }
    if (!session.hostKey.empty())
    {
        options.hostKey = session.hostKey;
    }
    options.initialDirectory = session.remoteDirectory;
    if (!session.password.empty())
    {
        options.password = session.password;
    }
    /* The proxy of the site, unless the file could not be read: a site
     * whose proxy is unusable is refused by 'open' rather than connected
     * around. */
    if (session.proxy.Active())
    {
        options.proxy = session.proxy;
    }
    options.ftp = session.ftp;
    options.tls = session.tls;
    options.s3 = session.s3;
    options.tunnel = session.tunnel;
    options.gssapi = session.gssapi;
    return options;
}

StoredSession SessionStore::FromSessionOptions(const std::string & name,
    const SessionOptions & options, const std::string & remoteDirectory,
    const std::string & localDirectory)
{
    StoredSession session;
    session.name = name;
    session.protocol = options.protocol;
    session.hostName = options.hostName;
    session.portNumber = options.portNumber;
    session.userName = options.userName;
    session.privateKeyFile = options.privateKeyFile;
    session.hostKey = options.hostKey;
    session.remoteDirectory = remoteDirectory;
    session.localDirectory = localDirectory;
    session.proxy = options.proxy;
    session.ftp = options.ftp;
    session.tls = options.tls;
    session.s3 = options.s3;
    session.tunnel = options.tunnel;
    session.gssapi = options.gssapi;
    // A connected session is not permission to persist its credentials.
    // To store these, give them explicitly to savesession -rawsettings.
    session.tunnel.password.clear();
    session.tunnel.keyPassphrase.clear();
    session.lastUsed = static_cast<unsigned long long>(time(NULL));
    return session;
}

} // namespace linscp
