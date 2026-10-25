/*
 * AWS Signature Version 4 - the string construction described in
 * "Signature Version 4 signing process", over the SHA-256 and HMAC
 * primitives shared with the sessions-file encryption (HashUtil).
 *
 * No I/O and no curl here: UnitTest.cpp checks these functions
 * against the published AWS example (the 20150830 signing key) and
 * against requests signed by botocore, and LiveS3Test.py checks the
 * same construction against a server that re-derives every signature.
 */

#include "S3SigV4.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>

#include "HashUtil.h"

namespace linscp {
namespace s3sig {

namespace {

bool IsUnreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '.' || c == '_' || c == '~';
}

void Hmac(const std::string & key, const std::string & data,
    std::string & out32)
{
    unsigned char raw[32];
    lscp_hmac_sha256(key.data(), key.size(), data.data(), data.size(),
        raw, sizeof(raw));
    out32.assign(reinterpret_cast<const char *>(raw), sizeof(raw));
}

/* Trim and collapse the runs of whitespace a header value may hold,
 * the way the canonical form requires. */
std::string NormalizeHeaderValue(std::string value)
{
    std::string out;
    bool inSpace = false;
    for (size_t i = 0; i < value.size(); i++)
    {
        const char c = value[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        {
            inSpace = !out.empty();
            continue;
        }
        if (inSpace)
        {
            out += ' ';
            inSpace = false;
        }
        out += c;
    }
    /* Leading space is dropped by the loop (out empty); trailing by
     * never appending after it. */
    return out;
}

bool Gmtime(unsigned long long epochSeconds, struct tm & out)
{
    const time_t t = static_cast<time_t>(epochSeconds);
    /* Avoid silently wrapping an unsigned timestamp when it does not fit
     * Linux's time_t, and never format an uninitialised tm after gmtime_r
     * fails for an out-of-range value. */
    if (t < 0 || static_cast<unsigned long long>(t) != epochSeconds ||
        gmtime_r(&t, &out) == NULL)
    {
        return false;
    }
    return out.tm_year >= -1900 && out.tm_year <= 8099;
}

} // namespace

std::string UriEncode(const std::string & value, bool keepSlash)
{
    static const char * digits = "0123456789ABCDEF";
    std::string out;
    for (size_t i = 0; i < value.size(); i++)
    {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if (IsUnreserved(c) || (keepSlash && c == '/'))
        {
            out += static_cast<char>(c);
        }
        else
        {
            out += '%';
            out += digits[c >> 4];
            out += digits[c & 15];
        }
    }
    return out;
}

std::string CanonicalQuery(const std::string & query)
{
    if (query.empty())
    {
        return std::string();
    }
    std::vector<std::pair<std::string, std::string> > pairs;
    size_t start = 0;
    while (start <= query.size())
    {
        const size_t amp = query.find('&', start);
        const std::string part = query.substr(start,
            amp == std::string::npos ? std::string::npos : amp - start);
        if (!part.empty())
        {
            const size_t eq = part.find('=');
            if (eq == std::string::npos)
            {
                pairs.push_back(std::make_pair(part, std::string()));
            }
            else
            {
                pairs.push_back(std::make_pair(part.substr(0, eq),
                    part.substr(eq + 1)));
            }
        }
        if (amp == std::string::npos)
        {
            break;
        }
        start = amp + 1;
    }
    std::sort(pairs.begin(), pairs.end());
    std::string out;
    for (size_t i = 0; i < pairs.size(); i++)
    {
        if (i > 0)
        {
            out += '&';
        }
        out += pairs[i].first;
        out += '=';
        out += pairs[i].second;
    }
    return out;
}

std::string CredentialScope(const std::string & dateStamp,
    const std::string & region, const std::string & service)
{
    return dateStamp + "/" + region + "/" + service + "/aws4_request";
}

std::string SigningKey(const std::string & secretAccessKey,
    const std::string & dateStamp, const std::string & region,
    const std::string & service)
{
    std::string keyDate;
    Hmac("AWS4" + secretAccessKey, dateStamp, keyDate);
    std::string keyRegion;
    Hmac(keyDate, region, keyRegion);
    std::string keyService;
    Hmac(keyRegion, service, keyService);
    std::string keySigning;
    Hmac(keyService, "aws4_request", keySigning);
    return keySigning;
}

std::string CanonicalRequest(const std::string & method,
    const std::string & uri, const std::string & query,
    const std::vector<std::pair<std::string, std::string> > & headers,
    const std::string & payloadHash)
{
    std::vector<std::pair<std::string, std::string> > sorted = headers;
    for (size_t i = 0; i < sorted.size(); i++)
    {
        std::string & name = sorted[i].first;
        for (size_t k = 0; k < name.size(); k++)
        {
            if (name[k] >= 'A' && name[k] <= 'Z')
            {
                name[k] = static_cast<char>(name[k] - 'A' + 'a');
            }
        }
        sorted[i].second = NormalizeHeaderValue(sorted[i].second);
    }
    std::stable_sort(sorted.begin(), sorted.end(),
        [](const std::pair<std::string, std::string> & a,
           const std::pair<std::string, std::string> & b) {
            return a.first < b.first;
        });

    /* Fold duplicate header names into a single comma-separated canonical
     * header line, as AWS Signature Version 4 specifies. */
    std::vector<std::pair<std::string, std::string> > folded;
    for (size_t i = 0; i < sorted.size(); i++)
    {
        if (!folded.empty() && folded.back().first == sorted[i].first)
        {
            folded.back().second += "," + sorted[i].second;
        }
        else
        {
            folded.push_back(sorted[i]);
        }
    }

    std::string canonical = method + "\n" + uri + "\n" +
        CanonicalQuery(query) + "\n";
    std::string names;
    for (size_t i = 0; i < folded.size(); i++)
    {
        if (i > 0)
        {
            names += ';';
        }
        names += folded[i].first;
        canonical += folded[i].first + ":" + folded[i].second + "\n";
    }
    canonical += "\n" + names + "\n" + payloadHash;
    return canonical;
}

std::string StringToSign(const std::string & amzDate,
    const std::string & scope, const std::string & canonicalRequest)
{
    return std::string("AWS4-HMAC-SHA256\n") + amzDate + "\n" + scope +
        "\n" + Sha256Hex(canonicalRequest);
}

std::string SignatureHex(const std::string & stringToSign,
    const std::string & signingKey)
{
    unsigned char raw[32];
    lscp_hmac_sha256(signingKey.data(), signingKey.size(),
        stringToSign.data(), stringToSign.size(), raw, sizeof(raw));
    return HexEncode(std::string(reinterpret_cast<const char *>(raw), 32));
}

std::string AuthorizationHeader(const std::string & accessKey,
    const std::string & scope, const std::string & signedHeaders,
    const std::string & signatureHex)
{
    return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope +
        ", SignedHeaders=" + signedHeaders +
        ", Signature=" + signatureHex;
}

std::string AmzDate(unsigned long long epochSeconds)
{
    struct tm value;
    if (!Gmtime(epochSeconds, value))
    {
        return std::string();
    }
    char buffer[32];
    if (strftime(buffer, sizeof(buffer), "%Y%m%dT%H%M%SZ", &value) == 0)
    {
        return std::string();
    }
    return buffer;
}

std::string DateStamp(unsigned long long epochSeconds)
{
    struct tm value;
    if (!Gmtime(epochSeconds, value))
    {
        return std::string();
    }
    char buffer[16];
    if (strftime(buffer, sizeof(buffer), "%Y%m%d", &value) == 0)
    {
        return std::string();
    }
    return buffer;
}

std::string HexEncode(const std::string & raw)
{
    static const char * digits = "0123456789abcdef";
    std::string hex;
    hex.resize(raw.size() * 2);
    for (size_t i = 0; i < raw.size(); i++)
    {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        hex[i * 2] = digits[c >> 4];
        hex[i * 2 + 1] = digits[c & 15];
    }
    return hex;
}

std::string Sha256Hex(const std::string & data)
{
    unsigned char raw[32];
    lscp_sha256(data.data(), data.size(), raw, sizeof(raw));
    return HexEncode(std::string(reinterpret_cast<const char *>(raw), 32));
}

SignedRequest Sign(const std::string & method, const std::string & uri,
    const std::string & query, const std::string & host,
    const std::vector<std::pair<std::string, std::string> > & extras,
    const std::string & payloadHash, unsigned long long epochSeconds,
    const std::string & region, const std::string & accessKey,
    const std::string & secretAccessKey)
{
    const std::string amzDate = AmzDate(epochSeconds);
    const std::string scope = CredentialScope(DateStamp(epochSeconds),
        region, "s3");

    SignedRequest result;
    result.headers.push_back(std::make_pair("host", host));
    result.headers.push_back(std::make_pair("x-amz-content-sha256",
        payloadHash));
    result.headers.push_back(std::make_pair("x-amz-date", amzDate));
    for (size_t i = 0; i < extras.size(); i++)
    {
        result.headers.push_back(extras[i]);
    }

    result.canonicalRequest = CanonicalRequest(method, uri, query,
        result.headers, payloadHash);
    const std::string toSign = StringToSign(amzDate, scope,
        result.canonicalRequest);
    const std::string key = SigningKey(secretAccessKey, DateStamp(epochSeconds),
        region, "s3");
    const std::string signature = SignatureHex(toSign, key);

    /* signedHeaders comes from the canonical request: the names line
     * after the blank header block. Re-derive it from the header set
     * rather than parsing, so both always agree. */
    std::vector<std::pair<std::string, std::string> > named = result.headers;
    for (size_t i = 0; i < named.size(); i++)
    {
        std::string & n = named[i].first;
        for (size_t k = 0; k < n.size(); k++)
        {
            if (n[k] >= 'A' && n[k] <= 'Z')
            {
                n[k] = static_cast<char>(n[k] - 'A' + 'a');
            }
        }
    }
    std::sort(named.begin(), named.end());
    std::string names;
    for (size_t i = 0; i < named.size(); i++)
    {
        if (i > 0 && named[i].first == named[i - 1].first)
        {
            continue;
        }
        if (!names.empty())
        {
            names += ';';
        }
        names += named[i].first;
    }
    result.signedHeaders = names;
    result.authorization = AuthorizationHeader(accessKey, scope, names,
        signature);
    return result;
}

} // namespace s3sig
} // namespace linscp
