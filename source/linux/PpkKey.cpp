#include "PpkKey.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <argon2.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace linscp {
namespace {
using Bytes = std::vector<unsigned char>;
constexpr size_t kMaxKeyFile = 4 * 1024 * 1024;
constexpr size_t kMaxField = 1024 * 1024;

struct Ppk {
    int version = 0;
    std::string algorithm;
    std::string encryption;
    std::string comment;
    std::string argonType;
    uint32_t memoryKiB = 0;
    uint32_t passes = 0;
    uint32_t parallelism = 0;
    Bytes salt;
    Bytes publicBlob;
    Bytes privateBlob;
    Bytes mac;
    ~Ppk()
    {
        if (!privateBlob.empty()) OPENSSL_cleanse(privateBlob.data(), privateBlob.size());
    }
};

bool Fail(std::string & error, const std::string & message)
{
    error = message;
    return false;
}

bool HexDecode(const std::string & text, Bytes & out)
{
    if ((text.size() & 1) != 0) return false;
    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2) {
        auto digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        const int hi = digit(text[i]), lo = digit(text[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

bool Base64Decode(const std::string & text, Bytes & out)
{
    if (text.empty() || text.size() > kMaxField || (text.size() % 4) != 0)
        return false;
    for (unsigned char c : text) {
        if (!(std::isalnum(c) || c == '+' || c == '/' || c == '=')) return false;
    }
    out.resize((text.size() / 4) * 3);
    const int n = EVP_DecodeBlock(out.data(),
        reinterpret_cast<const unsigned char *>(text.data()),
        static_cast<int>(text.size()));
    if (n < 0) return false;
    size_t actual = static_cast<size_t>(n);
    if (!text.empty() && text.back() == '=') --actual;
    if (text.size() > 1 && text[text.size() - 2] == '=') --actual;
    out.resize(actual);
    return true;
}

std::string Base64Encode(const Bytes & bytes)
{
    if (bytes.empty()) return {};
    std::string out(4 * ((bytes.size() + 2) / 3), '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&out[0]),
        bytes.data(), static_cast<int>(bytes.size()));
    if (n < 0) return {};
    out.resize(static_cast<size_t>(n));
    return out;
}

void StripTrailingCR(std::string & line)
{
    if (!line.empty() && line.back() == '\r') line.pop_back();
}

bool ReadFieldLines(std::istream & in, size_t count, Bytes & out)
{
    if (count == 0 || count > kMaxField) return false;
    std::string encoded, line;
    for (size_t i = 0; i < count; ++i) {
        if (!std::getline(in, line)) return false;
        StripTrailingCR(line);
        if (line.size() > kMaxField || encoded.size() + line.size() > kMaxField)
            return false;
        encoded += line;
    }
    return Base64Decode(encoded, out);
}

bool ParseDecimal(const std::string & text, uint64_t & value)
{
    if (text.empty()) return false;
    value = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = c - '0';
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) return false;
        value = value * 10 + digit;
    }
    return true;
}

bool ReadHeader(std::istream & in, std::string & name, std::string & value)
{
    std::string line;
    if (!std::getline(in, line)) return false;
    StripTrailingCR(line);
    if (line.size() > kMaxField) return false;
    const auto colon = line.find(':');
    if (colon == std::string::npos) return false;
    name = line.substr(0, colon);
    size_t start = colon + 1;
    if (start < line.size() && line[start] == ' ') ++start;
    value = line.substr(start);
    return true;
}

bool ParsePpk(const std::string & path, Ppk & ppk, std::string & error)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) return Fail(error, "Cannot open PPK key file");
    file.seekg(0, std::ios::end);
    const std::streamoff fileSize = static_cast<std::streamoff>(file.tellg());
    if (fileSize <= 0 || static_cast<uint64_t>(fileSize) > kMaxKeyFile)
        return Fail(error, "PPK key file is empty or too large");
    file.seekg(0, std::ios::beg);

    std::string first;
    if (!std::getline(file, first)) return Fail(error, "Invalid PPK header");
    StripTrailingCR(first);
    const std::string prefix = "PuTTY-User-Key-File-";
    if (first.compare(0, prefix.size(), prefix) != 0)
        return Fail(error, "Not a PPK key file");
    const auto colon = first.find(':');
    if (colon == std::string::npos) return Fail(error, "Invalid PPK header");
    uint64_t version = 0;
    if (!ParseDecimal(first.substr(prefix.size(), colon - prefix.size()), version) ||
        version > 255)
        return Fail(error, "Invalid PPK version");
    ppk.version = static_cast<int>(version);
    if (ppk.version != 2 && ppk.version != 3)
        return Fail(error, "Only PPK v2 and v3 key files are supported");
    ppk.algorithm = first.substr(colon + 1);
    if (!ppk.algorithm.empty() && ppk.algorithm[0] == ' ')
        ppk.algorithm.erase(ppk.algorithm.begin());

    std::string name, value;
    if (!ReadHeader(file, name, ppk.encryption) || name != "Encryption" ||
        (ppk.encryption != "none" && ppk.encryption != "aes256-cbc"))
        return Fail(error, "Invalid or unsupported PPK encryption header");
    if (!ReadHeader(file, name, ppk.comment) || name != "Comment")
        return Fail(error, "Invalid PPK comment header");
    if (!ReadHeader(file, name, value) || name != "Public-Lines")
        return Fail(error, "Invalid PPK public key section");
    uint64_t publicLineCount = 0;
    if (!ParseDecimal(value, publicLineCount) || publicLineCount > std::numeric_limits<size_t>::max())
        return Fail(error, "Invalid PPK public key line count");
    const size_t publicLines = static_cast<size_t>(publicLineCount);
    if (!ReadFieldLines(file, publicLines, ppk.publicBlob))
        return Fail(error, "Invalid PPK public key data");

    if (ppk.version == 3) {
        if (!ReadHeader(file, name, value) || name != "Key-Derivation")
            return Fail(error, "Invalid PPK v3 key derivation header");
        ppk.argonType = value;
        if (ppk.encryption == "aes256-cbc") {
            if (ppk.argonType != "Argon2d" && ppk.argonType != "Argon2i" &&
                ppk.argonType != "Argon2id")
                return Fail(error, "Unsupported PPK v3 key derivation algorithm");
            if (!ReadHeader(file, name, value) || name != "Argon2-Memory")
                return Fail(error, "Missing PPK Argon2 memory parameter");
            uint64_t parameter = 0;
            if (!ParseDecimal(value, parameter) || parameter > UINT32_MAX)
                return Fail(error, "Invalid PPK Argon2 memory parameter");
            ppk.memoryKiB = static_cast<uint32_t>(parameter);
            if (!ReadHeader(file, name, value) || name != "Argon2-Passes")
                return Fail(error, "Missing PPK Argon2 passes parameter");
            if (!ParseDecimal(value, parameter) || parameter > UINT32_MAX)
                return Fail(error, "Invalid PPK Argon2 passes parameter");
            ppk.passes = static_cast<uint32_t>(parameter);
            if (!ReadHeader(file, name, value) || name != "Argon2-Parallelism")
                return Fail(error, "Missing PPK Argon2 parallelism parameter");
            if (!ParseDecimal(value, parameter) || parameter > UINT32_MAX)
                return Fail(error, "Invalid PPK Argon2 parallelism parameter");
            ppk.parallelism = static_cast<uint32_t>(parameter);
            if (!ReadHeader(file, name, value) || name != "Argon2-Salt" ||
                !HexDecode(value, ppk.salt) || ppk.salt.empty() ||
                ppk.salt.size() > 1024)
                return Fail(error, "Invalid PPK Argon2 salt");
            // Bound work factors before passing an untrusted key file to Argon2.
            if (ppk.memoryKiB < 8 || ppk.memoryKiB > 256 * 1024 ||
                ppk.passes == 0 || ppk.passes > 100 ||
                ppk.parallelism == 0 || ppk.parallelism > 64)
                return Fail(error, "PPK Argon2 parameters are outside safe limits");
        } else if (ppk.argonType != "none") {
            return Fail(error, "Unencrypted PPK v3 key has unexpected derivation parameters");
        }
    }

    if (!ReadHeader(file, name, value) || name != "Private-Lines")
        return Fail(error, "Invalid PPK private key section");
    uint64_t privateLineCount = 0;
    if (!ParseDecimal(value, privateLineCount) || privateLineCount > std::numeric_limits<size_t>::max())
        return Fail(error, "Invalid PPK private key line count");
    const size_t privateLines = static_cast<size_t>(privateLineCount);
    if (!ReadFieldLines(file, privateLines, ppk.privateBlob))
        return Fail(error, "Invalid PPK private key data");
    if (!ReadHeader(file, name, value) || name != "Private-MAC" ||
        !HexDecode(value, ppk.mac) || (ppk.mac.size() != 20 && ppk.mac.size() != 32))
        return Fail(error, "Invalid PPK private MAC");
    std::string trailing;
    while (std::getline(file, trailing)) {
        StripTrailingCR(trailing);
        if (!trailing.empty()) return Fail(error, "Unexpected data after PPK MAC");
    }

    if (ppk.algorithm.empty() || ppk.publicBlob.empty() || ppk.privateBlob.empty())
        return Fail(error, "Incomplete PPK key data");
    return true;
}

void PutU32(Bytes & out, uint32_t n)
{
    out.push_back(static_cast<unsigned char>(n >> 24));
    out.push_back(static_cast<unsigned char>(n >> 16));
    out.push_back(static_cast<unsigned char>(n >> 8));
    out.push_back(static_cast<unsigned char>(n));
}

void PutString(Bytes & out, const Bytes & value)
{
    PutU32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}
void PutString(Bytes & out, const std::string & value)
{
    PutU32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

bool GetString(const Bytes & in, size_t & pos, Bytes & value)
{
    if (pos + 4 > in.size()) return false;
    uint32_t n = (static_cast<uint32_t>(in[pos]) << 24) |
        (static_cast<uint32_t>(in[pos + 1]) << 16) |
        (static_cast<uint32_t>(in[pos + 2]) << 8) | in[pos + 3];
    pos += 4;
    if (n > kMaxField || pos + n > in.size()) return false;
    value.assign(in.begin() + pos, in.begin() + pos + n);
    pos += n;
    return true;
}

bool GetMpint(const Bytes & in, size_t & pos, BIGNUM ** bn)
{
    Bytes value;
    if (!GetString(in, pos, value) || value.empty()) return false;
    if (value[0] & 0x80) return false; // PPK keys use non-negative mpints.
    while (value.size() > 1 && value[0] == 0) value.erase(value.begin());
    *bn = BN_bin2bn(value.data(), static_cast<int>(value.size()), nullptr);
    return *bn != nullptr;
}

std::string CleanComment(const std::string & comment)
{
    std::string out = comment;
    for (char & c : out)
        if (c == '\n' || c == '\r' || c == '\0') c = ' ';
    return out;
}

bool PrivateTailOk(const Ppk & ppk, size_t pos)
{
    if (pos == ppk.privateBlob.size()) return true;
    return ppk.encryption == "aes256-cbc" && pos < ppk.privateBlob.size() &&
        ppk.privateBlob.size() - pos <= 15;
}

bool BuildPrivateKey(const Ppk & ppk, EVP_PKEY ** result, std::string & error)
{
    size_t pos = 0;
    Bytes field;
    std::string algorithm;
    if (!GetString(ppk.publicBlob, pos, field))
        return Fail(error, "Malformed SSH public key blob");
    algorithm.assign(field.begin(), field.end());
    if (algorithm != ppk.algorithm)
        return Fail(error, "PPK algorithm does not match its public key blob");

    auto readBn = [&](BIGNUM ** bn) { return GetMpint(ppk.publicBlob, pos, bn); };
    EVP_PKEY * key = nullptr;
    if (algorithm == "ssh-rsa") {
        BIGNUM * e = nullptr, *n = nullptr, *d = nullptr, *p = nullptr,
            *q = nullptr, *iqmp = nullptr;
        bool ok = readBn(&e) && readBn(&n) && pos == ppk.publicBlob.size();
        pos = 0;
        ok = ok && GetMpint(ppk.privateBlob, pos, &d) &&
            GetMpint(ppk.privateBlob, pos, &p) && GetMpint(ppk.privateBlob, pos, &q) &&
            GetMpint(ppk.privateBlob, pos, &iqmp) && PrivateTailOk(ppk, pos);
        RSA * rsa = ok ? RSA_new() : nullptr;
        if (rsa && RSA_set0_key(rsa, n, e, d) == 1) {
            n = e = d = nullptr;
            if (RSA_set0_factors(rsa, p, q) == 1) {
                p = q = nullptr;
                BIGNUM * dmp1 = BN_new(), *dmq1 = BN_new();
                BIGNUM * pMinusOne = BN_dup(RSA_get0_p(rsa));
                BIGNUM * qMinusOne = BN_dup(RSA_get0_q(rsa));
                // Compute CRT exponents rather than trusting any redundant data.
                BN_CTX * ctx = BN_CTX_new();
                const bool crt = dmp1 && dmq1 && pMinusOne && qMinusOne && ctx &&
                    BN_sub_word(pMinusOne, 1) == 1 && BN_sub_word(qMinusOne, 1) == 1 &&
                    BN_mod(dmp1, RSA_get0_d(rsa), pMinusOne, ctx) == 1 &&
                    BN_mod(dmq1, RSA_get0_d(rsa), qMinusOne, ctx) == 1;
                if (crt && RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) == 1) {
                    dmp1 = dmq1 = iqmp = nullptr;
                    if (RSA_check_key(rsa) == 1) {
                        key = EVP_PKEY_new();
                        if (!key || EVP_PKEY_assign_RSA(key, rsa) != 1) {
                            EVP_PKEY_free(key); key = nullptr;
                        } else rsa = nullptr;
                    }
                }
                BN_free(dmp1); BN_free(dmq1); BN_free(pMinusOne); BN_free(qMinusOne);
                BN_CTX_free(ctx);
            }
        }
        RSA_free(rsa); BN_free(e); BN_free(n); BN_clear_free(d); BN_clear_free(p);
        BN_clear_free(q); BN_clear_free(iqmp);
    } else if (algorithm == "ssh-dss") {
        BIGNUM * p = nullptr, *q = nullptr, *g = nullptr, *y = nullptr, *x = nullptr;
        bool ok = readBn(&p) && readBn(&q) && readBn(&g) && readBn(&y) &&
            pos == ppk.publicBlob.size();
        pos = 0;
        ok = ok && GetMpint(ppk.privateBlob, pos, &x) && PrivateTailOk(ppk, pos);
        BN_CTX * bnCtx = ok ? BN_CTX_new() : nullptr;
        BIGNUM * calculatedY = ok ? BN_new() : nullptr;
        ok = ok && bnCtx && calculatedY &&
            BN_mod_exp(calculatedY, g, x, p, bnCtx) == 1 && BN_cmp(calculatedY, y) == 0;
        BN_CTX_free(bnCtx); BN_free(calculatedY);
        DSA * dsa = ok ? DSA_new() : nullptr;
        if (dsa && DSA_set0_pqg(dsa, p, q, g) == 1) {
            p = q = g = nullptr;
            if (DSA_set0_key(dsa, y, x) == 1) {
                y = x = nullptr;
                key = EVP_PKEY_new();
                if (!key || EVP_PKEY_assign_DSA(key, dsa) != 1) {
                    EVP_PKEY_free(key); key = nullptr;
                } else dsa = nullptr;
            }
        }
        DSA_free(dsa); BN_clear_free(p); BN_clear_free(q); BN_free(g); BN_free(y);
        BN_clear_free(x);
    } else if (algorithm.rfind("ecdsa-sha2-", 0) == 0) {
        Bytes curveBytes, point;
        if (!GetString(ppk.publicBlob, pos, curveBytes) || !GetString(ppk.publicBlob, pos, point) ||
            pos != ppk.publicBlob.size())
            return Fail(error, "Malformed ECDSA public key blob");
        pos = 0;
        std::string curve(curveBytes.begin(), curveBytes.end());
        if (algorithm != "ecdsa-sha2-" + curve)
            return Fail(error, "ECDSA curve does not match the PPK algorithm");
        int nid = curve == "nistp256" ? NID_X9_62_prime256v1 :
            curve == "nistp384" ? NID_secp384r1 : curve == "nistp521" ? NID_secp521r1 : NID_undef;
        BIGNUM * scalar = nullptr;
        if (nid == NID_undef || !GetMpint(ppk.privateBlob, pos, &scalar) ||
            !PrivateTailOk(ppk, pos)) {
            BN_free(scalar); return Fail(error, "Unsupported or malformed ECDSA PPK key");
        }
        EC_KEY * ec = EC_KEY_new_by_curve_name(nid);
        const EC_GROUP * group = ec ? EC_KEY_get0_group(ec) : nullptr;
        EC_POINT * publicPoint = group ? EC_POINT_new(group) : nullptr;
        bool ok = ec && publicPoint && EC_POINT_oct2point(group, publicPoint,
            point.data(), point.size(), nullptr) == 1 &&
            EC_KEY_set_private_key(ec, scalar) == 1 &&
            EC_KEY_set_public_key(ec, publicPoint) == 1 && EC_KEY_check_key(ec) == 1;
        if (ok) {
            key = EVP_PKEY_new();
            if (!key || EVP_PKEY_assign_EC_KEY(key, ec) != 1) {
                EVP_PKEY_free(key); key = nullptr;
            } else ec = nullptr;
        }
        EC_POINT_free(publicPoint); EC_KEY_free(ec); BN_clear_free(scalar);
    } else if (algorithm == "ssh-ed25519" || algorithm == "ssh-ed448") {
        Bytes publicBytes;
        if (!GetString(ppk.publicBlob, pos, publicBytes) || pos != ppk.publicBlob.size())
            return Fail(error, "Malformed Edwards public key blob");
        pos = 0;
        const int expected = algorithm == "ssh-ed25519" ? 32 : 57;
        Bytes secret;
        if (!GetString(ppk.privateBlob, pos, secret) || !PrivateTailOk(ppk, pos))
            return Fail(error, "Malformed Edwards private key blob");
        // Some PPK producers encode the seed as an mpint and include one
        // leading sign byte; accept that representation as well as the
        // protocol's fixed-length string form.
        if (secret.size() == static_cast<size_t>(expected + 1) && secret[0] == 0)
            secret.erase(secret.begin());
        if (secret.size() == static_cast<size_t>(expected * 2) &&
            publicBytes.size() == static_cast<size_t>(expected) &&
            CRYPTO_memcmp(secret.data() + expected, publicBytes.data(), expected) == 0)
            secret.resize(static_cast<size_t>(expected));
        if (secret.size() != static_cast<size_t>(expected)) {
            OPENSSL_cleanse(secret.data(), secret.size());
            return Fail(error, "Invalid Edwards private key size");
        }
        const int type = algorithm == "ssh-ed25519" ? EVP_PKEY_ED25519 : EVP_PKEY_ED448;
        key = EVP_PKEY_new_raw_private_key(type, nullptr, secret.data(), secret.size());
        OPENSSL_cleanse(secret.data(), secret.size());
        if (key) {
            Bytes derived(publicBytes.size());
            size_t derivedSize = derived.size();
            if (EVP_PKEY_get_raw_public_key(key, derived.data(), &derivedSize) != 1 ||
                derivedSize != publicBytes.size() ||
                CRYPTO_memcmp(derived.data(), publicBytes.data(), derivedSize) != 0) {
                EVP_PKEY_free(key); key = nullptr;
            }
        }
    } else {
        return Fail(error, "Unsupported PPK key algorithm: " + algorithm);
    }
    if (!key) return Fail(error, "PPK private key components are invalid or inconsistent");
    *result = key;
    return true;
}

bool BuildPem(const Ppk & ppk, const Bytes & privateBytes, std::string & pem,
    std::string & error, const std::string * outputPassphrase = nullptr)
{
    Ppk copy = ppk;
    copy.privateBlob = privateBytes;
    EVP_PKEY * key = nullptr;
    if (!BuildPrivateKey(copy, &key, error)) {
        OPENSSL_cleanse(copy.privateBlob.data(), copy.privateBlob.size());
        return false;
    }
    BIO * bio = BIO_new(BIO_s_mem());
    const EVP_CIPHER * outputCipher = outputPassphrase != nullptr ? EVP_aes_256_cbc() : nullptr;
    const unsigned char * password = outputPassphrase != nullptr ?
        reinterpret_cast<const unsigned char *>(outputPassphrase->data()) : nullptr;
    const int passwordSize = outputPassphrase != nullptr ?
        static_cast<int>(outputPassphrase->size()) : 0;
    const bool ok = bio && PEM_write_bio_PrivateKey(bio, key, outputCipher,
        password, passwordSize, nullptr, nullptr) == 1;
    if (ok) {
        char * data = nullptr;
        const long size = BIO_get_mem_data(bio, &data);
        if (size > 0) pem.assign(data, static_cast<size_t>(size));
    }
    BIO_free(bio); EVP_PKEY_free(key);
    OPENSSL_cleanse(copy.privateBlob.data(), copy.privateBlob.size());
    if (!ok || pem.empty()) return Fail(error, "Could not encode PPK key as PEM");
    return true;
}

bool DecryptAndVerify(const Ppk & ppk, const std::string & passphrase,
    Bytes & plain, std::string & error)
{
    Bytes keyMaterial;
    if (ppk.encryption == "none") {
        plain = ppk.privateBlob;
    } else if (ppk.version == 2) {
        Bytes input(4, 0);
        for (uint32_t i = 0; i < 2; ++i) {
            Bytes block = input;
            block[3] = static_cast<unsigned char>(i);
            block.insert(block.end(), passphrase.begin(), passphrase.end());
            unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int len = 0;
            if (!EVP_Digest(block.data(), block.size(), digest, &len, EVP_sha1(), nullptr)) {
                OPENSSL_cleanse(block.data(), block.size());
                OPENSSL_cleanse(digest, sizeof(digest));
                return Fail(error, "Could not derive PPK v2 encryption key");
            }
            keyMaterial.insert(keyMaterial.end(), digest, digest + len);
            OPENSSL_cleanse(block.data(), block.size());
            OPENSSL_cleanse(digest, sizeof(digest));
        }
        keyMaterial.resize(32);
        OPENSSL_cleanse(input.data(), input.size());
    } else {
        keyMaterial.resize(80);
        int rc = -1;
        const auto * password = reinterpret_cast<const uint8_t *>(passphrase.data());
        if (ppk.argonType == "Argon2d") rc = argon2d_hash_raw(ppk.passes,
            ppk.memoryKiB, ppk.parallelism, password, passphrase.size(), ppk.salt.data(),
            ppk.salt.size(), keyMaterial.data(), keyMaterial.size());
        else if (ppk.argonType == "Argon2i") rc = argon2i_hash_raw(ppk.passes,
            ppk.memoryKiB, ppk.parallelism, password, passphrase.size(), ppk.salt.data(),
            ppk.salt.size(), keyMaterial.data(), keyMaterial.size());
        else rc = argon2id_hash_raw(ppk.passes, ppk.memoryKiB, ppk.parallelism,
            password, passphrase.size(), ppk.salt.data(), ppk.salt.size(),
            keyMaterial.data(), keyMaterial.size());
        if (rc != ARGON2_OK) {
            OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());
            return Fail(error, "PPK v3 Argon2 key derivation failed");
        }
    }

    if (ppk.encryption == "aes256-cbc") {
        if (ppk.privateBlob.empty() || ppk.privateBlob.size() % 16 != 0) {
            OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());
            return Fail(error, "Invalid AES-encrypted PPK private key length");
        }
        const unsigned char * aesKey = keyMaterial.data();
        const unsigned char * iv = ppk.version == 2 ?
            reinterpret_cast<const unsigned char *>("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0") :
            keyMaterial.data() + 32;
        EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
        plain.resize(ppk.privateBlob.size() + 16);
        int first = 0, last = 0;
        const bool ok = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey, iv) == 1 &&
            EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
            EVP_DecryptUpdate(ctx, plain.data(), &first, ppk.privateBlob.data(),
                static_cast<int>(ppk.privateBlob.size())) == 1 &&
            EVP_DecryptFinal_ex(ctx, plain.data() + first, &last) == 1;
        EVP_CIPHER_CTX_free(ctx);
        if (!ok) {
            OPENSSL_cleanse(plain.data(), plain.size());
            OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());
            return Fail(error, "Could not decrypt PPK private key");
        }
        plain.resize(static_cast<size_t>(first + last));
    }

    Bytes macKey;
    static const unsigned char macLabel[] = "putty-private-key-file-mac-key";
    if (ppk.version == 2 && ppk.encryption == "aes256-cbc") {
        Bytes macInput(macLabel, macLabel + sizeof(macLabel) - 1);
        macInput.insert(macInput.end(), passphrase.begin(), passphrase.end());
        unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int digestSize = 0;
        const bool derived = EVP_Digest(macInput.data(), macInput.size(), digest,
            &digestSize, EVP_sha1(), nullptr) == 1;
        OPENSSL_cleanse(macInput.data(), macInput.size());
        if (!derived) {
            OPENSSL_cleanse(plain.data(), plain.size());
            OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());
            return Fail(error, "Could not derive PPK v2 integrity key");
        }
        macKey.assign(digest, digest + digestSize);
        OPENSSL_cleanse(digest, sizeof(digest));
    } else if (ppk.version == 3 && ppk.encryption == "aes256-cbc") {
        macKey.assign(keyMaterial.begin() + 48, keyMaterial.end());
    } else {
        macKey.assign(macLabel, macLabel + sizeof(macLabel) - 1);
    }
    Bytes data;
    PutString(data, ppk.algorithm); PutString(data, ppk.encryption);
    PutString(data, ppk.comment); PutString(data, ppk.publicBlob); PutString(data, plain);
    std::array<unsigned char, EVP_MAX_MD_SIZE> calculated{};
    unsigned int calculatedSize = 0;
    const EVP_MD * digest = ppk.version == 2 ? EVP_sha1() : EVP_sha256();
    const bool hmacReady = HMAC(digest, macKey.data(), static_cast<int>(macKey.size()),
        data.data(), data.size(), calculated.data(), &calculatedSize) != nullptr;
    const bool macValid = hmacReady && calculatedSize == ppk.mac.size() &&
        CRYPTO_memcmp(calculated.data(), ppk.mac.data(), ppk.mac.size()) == 0;
    OPENSSL_cleanse(macKey.data(), macKey.size());
    OPENSSL_cleanse(data.data(), data.size());
    OPENSSL_cleanse(calculated.data(), calculated.size());
    if (!macValid) {
        OPENSSL_cleanse(plain.data(), plain.size());
        OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());
        return Fail(error, "PPK integrity check failed (incorrect passphrase or damaged key file)");
    }
    OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());
    return true;
}

} // namespace

bool IsPpkKeyFile(const std::string & path)
{
    std::ifstream file(path, std::ios::binary);
    std::string line;
    return file && std::getline(file, line) &&
        line.compare(0, std::strlen("PuTTY-User-Key-File-"), "PuTTY-User-Key-File-") == 0;
}

bool PpkPublicAuthorizedLine(const std::string & path, const std::string & passphrase,
    std::string & line, std::string & error)
{
    line.clear();
    error.clear();
    Ppk ppk;
    if (!ParsePpk(path, ppk, error)) return false;
    Bytes plain;
    if (!DecryptAndVerify(ppk, passphrase, plain, error)) return false;
    Ppk checked = ppk;
    checked.privateBlob = plain;
    EVP_PKEY * key = nullptr;
    const bool validKey = BuildPrivateKey(checked, &key, error);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(checked.privateBlob.data(), checked.privateBlob.size());
    OPENSSL_cleanse(plain.data(), plain.size());
    if (!validKey) return false;
    Bytes field;
    size_t pos = 0;
    if (!GetString(ppk.publicBlob, pos, field))
        return Fail(error, "Malformed SSH public key blob");
    const std::string type(field.begin(), field.end());
    if (type != ppk.algorithm || pos >= ppk.publicBlob.size())
        return Fail(error, "Invalid SSH public key blob in PPK file");
    line = type + " " + Base64Encode(ppk.publicBlob);
    const std::string comment = CleanComment(ppk.comment);
    if (!comment.empty()) line += " " + comment;
    return true;
}

bool PpkPrivateKeyPem(const std::string & path, const std::string & passphrase,
    std::string & pem, std::string & error)
{
    pem.clear();
    error.clear();
    Ppk ppk;
    if (!ParsePpk(path, ppk, error)) return false;
    Bytes plain;
    if (!DecryptAndVerify(ppk, passphrase, plain, error)) return false;
    const bool ok = BuildPem(ppk, plain, pem, error);
    OPENSSL_cleanse(plain.data(), plain.size());
    return ok;
}

bool ConvertPpkToOpenSsh(const std::string & input, const std::string & output,
    const std::string & passphrase, std::string & error)
{
    error.clear();
    Ppk ppk;
    if (!ParsePpk(input, ppk, error)) return false;
    Bytes plain;
    if (!DecryptAndVerify(ppk, passphrase, plain, error)) return false;
    std::string pem;
    const std::string * outputPassphrase = ppk.encryption == "aes256-cbc" ?
        &passphrase : nullptr;
    const bool encoded = BuildPem(ppk, plain, pem, error, outputPassphrase);
    OPENSSL_cleanse(plain.data(), plain.size());
    if (!encoded) return false;
    const int fd = open(output.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        OPENSSL_cleanse(pem.data(), pem.size());
        return Fail(error, errno == EEXIST ?
            "Output file already exists; refusing to overwrite it" : "Cannot create output key file");
    }
    size_t written = 0;
    while (written < pem.size()) {
        const ssize_t n = write(fd, pem.data() + written, pem.size() - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        written += static_cast<size_t>(n);
    }
    const bool ok = written == pem.size() && fsync(fd) == 0;
    const int savedErrno = errno;
    close(fd);
    OPENSSL_cleanse(pem.data(), pem.size());
    if (!ok) {
        unlink(output.c_str()); errno = savedErrno;
        return Fail(error, "Failed writing converted key file");
    }
    return true;
}

} // namespace linscp
