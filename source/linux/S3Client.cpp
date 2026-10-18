/*
 * Amazon S3 over HTTPS: see S3Client.h for the model (path-style
 * buckets, delimiter directories, marker objects, SigV4 everywhere).
 *
 * One curl process per request, no connection of its own - the same
 * shape as the other curl-backed protocols, except that every request
 * must be signed first and every answer is XML (or a HEAD header
 * block) rather than an 'ls -l' line. The status code comes from
 * --write-out instead of curl's exit code: without -f, HTTP errors
 * reach us with the S3 error document intact, which is what turns a
 * bare 403 into "InvalidAccessKeyId: The AWS Access Key Id you
 * provided does not exist in this account".
 */

#include "S3Client.h"

#include "LocalFs.h"
#include "PathUtil.h"
#include "Platform.h"
#include "ProtocolClient.h"
#include "S3SigV4.h"

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

#include <unistd.h>

namespace linscp {

namespace {

/* Hash of the empty body: S3 wants this header on every signed
 * request that has no payload; uploads declare UNSIGNED-PAYLOAD,
 * which is valid over TLS (the only transport an s3 site gets). */
const char * const kEmptySha256 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const char * const kUnsignedPayload = "UNSIGNED-PAYLOAD";

/* S3 requires every non-final multipart part to be at least 5 MiB. Use an
 * 8 MiB floor (comfortably above the service minimum) and increase the part
 * size for larger objects so no upload exceeds the 10,000-part limit. */
const unsigned long long kS3MinimumPartSize = 8ull * 1024 * 1024;
const unsigned long long kS3MultipartThreshold = 16ull * 1024 * 1024;
const unsigned long long kS3MaximumParts = 10000ull;
const unsigned long long kS3MaximumObjectSize = 5ull * 1024 * 1024 * 1024 * 1024;

std::string ToLower(const std::string & text)
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

bool StartsWith(const std::string & text, const std::string & prefix)
{
    return text.size() >= prefix.size() &&
        text.compare(0, prefix.size(), prefix) == 0;
}

bool EndsWith(const std::string & text, const char * suffix)
{
    const size_t len = strlen(suffix);
    return text.size() >= len &&
        text.compare(text.size() - len, len, suffix) == 0;
}

char * DupString(const std::string & text)
{
    char * copy = static_cast<char *>(malloc(text.size() + 1));
    if (copy != NULL)
    {
        memcpy(copy, text.data(), text.size());
        copy[text.size()] = '\0';
    }
    return copy;
}

const std::string & CurlExecutable()
{
    static const std::string executable = [] {
        std::string found = FindExecutableOnPath("curl");
        return found.empty() ? std::string("curl") : found;
    }();
    return executable;
}

/* ---- site and path layout ---------------------------------------------- */

struct S3Site
{
    bool ok;
    std::string error;
    std::string accessKey;
    std::string secretKey;
    std::string region;
    /* What goes into the Host header: host plus port when it is not
     * the default, exactly as curl will send it. */
    std::string authority;

    S3Site() : ok(false) {}
};

std::string RegionFromEnvironment()
{
    const char * region = getenv("AWS_REGION");
    if (region != NULL && region[0] != '\0')
    {
        return region;
    }
    region = getenv("AWS_DEFAULT_REGION");
    if (region != NULL && region[0] != '\0')
    {
        return region;
    }
    return std::string();
}

/* s3.<region>.amazonaws.com carries the region in the host name;
 * anything else falls back to the environment, then us-east-1. */
std::string RegionFromHost(const std::string & host)
{
    const std::string lower = ToLower(host);
    if (lower != "amazonaws.com" && !EndsWith(lower, ".amazonaws.com") &&
        !EndsWith(lower, ".amazonaws.com.cn"))
    {
        return std::string();
    }
    std::istringstream stream(lower);
    std::string label;
    std::vector<std::string> labels;
    while (std::getline(stream, label, '.'))
    {
        labels.push_back(label);
    }
    for (size_t i = 0; i + 1 < labels.size(); i++)
    {
        if (labels[i] != "s3")
        {
            continue;
        }
        const std::string & candidate = labels[i + 1];
        if (candidate == "amazonaws")
        {
            return "us-east-1";
        }
        /* Region labels always carry a dash (us-east-1, eu-west-1,
         * ...); 'dualstack' and friends do not. */
        if (candidate.find('-') != std::string::npos)
        {
            return candidate;
        }
    }
    return std::string();
}

S3Site S3SiteOf(const SessionOptions & options)
{
    S3Site site;
    if (ToLower(options.protocol) != "s3")
    {
        site.error = "Not an S3 session.";
        return site;
    }
    if (options.userName.empty())
    {
        site.error = "An Amazon S3 site needs its access key ID as the user "
            "name: s3://ACCESSKEY@host/bucket/ or -username=ACCESSKEY.";
        return site;
    }
    if (options.password.empty())
    {
        site.error = "An Amazon S3 site needs its secret access key as the "
            "password: -password=SECRET or the LINSCP_PASSWORD "
            "environment variable. Every request is signed with AWS "
            "Signature Version 4, which is what authenticates S3.";
        return site;
    }
    site.accessKey = options.userName;
    site.secretKey = options.password;
    site.region = RegionFromEnvironment();
    if (site.region.empty())
    {
        site.region = RegionFromHost(options.hostName);
    }
    if (site.region.empty())
    {
        site.region = "us-east-1";
    }
    site.authority = options.hostName;
    if (options.portNumber > 0 && options.portNumber != 443)
    {
        site.authority += ":" + std::to_string(options.portNumber);
    }
    site.ok = true;
    return site;
}

/* Percent-encode every segment of an absolute path; '/' survives. */
std::string EncodePath(const std::string & path)
{
    std::string out;
    if (path.empty() || path[0] != '/')
    {
        out += '/';
    }
    size_t start = 0;
    while (start <= path.size())
    {
        const size_t slash = path.find('/', start);
        const std::string part = path.substr(start,
            slash == std::string::npos ? std::string::npos : slash - start);
        if (!part.empty())
        {
            out += s3sig::UriEncode(part, false);
        }
        if (slash == std::string::npos)
        {
            break;
        }
        out += '/';
        start = slash + 1;
    }
    return out;
}

/*
 * '/bucket/key...' -> bucket and key. A key keeps a trailing slash:
 * 'dir/' is the marker object, 'dir' would be a file name. No bucket
 * in the path is an error (the caller checks for '/' itself first).
 */
bool SplitBucketKey(const std::string & path, std::string & bucket,
    std::string & key, std::string & error)
{
    if (path.empty() || path[0] != '/' || path.size() < 2)
    {
        error = "There is no bucket in the remote path '" + path +
            "' (expected /bucket/...).";
        return false;
    }
    const size_t slash = path.find('/', 1);
    if (slash == std::string::npos)
    {
        bucket = path.substr(1);
        key.clear();
    }
    else
    {
        bucket = path.substr(1, slash - 1);
        key = path.substr(slash + 1);
    }
    if (bucket.empty())
    {
        error = "There is no bucket in the remote path '" + path +
            "' (expected /bucket/...).";
        return false;
    }
    return true;
}

std::string S3Url(const S3Site & site, const std::string & encodedPath,
    const std::string & query)
{
    std::string url = "https://" + site.authority + encodedPath;
    if (!query.empty())
    {
        url += "?" + query;
    }
    return url;
}

/* ---- responses ---------------------------------------------------------- */

struct S3Response
{
    int curlCode;    /* curl's own exit code; 0 even for HTTP errors */
    int httpCode;    /* from --write-out; 0 when nothing was answered */
    std::string out; /* body (or HEAD headers), without the status tail */
    std::string err; /* curl stderr */

    S3Response() : curlCode(0), httpCode(0) {}
};

/*
 * Splits 'BODY\nNNN' (what -w "\n%{http_code}" appends). Returns the
 * code, 0 when the last line is not one, and hands the body back.
 */
int SplitWriteOut(const std::string & out, std::string & body)
{
    const size_t newline = out.rfind('\n');
    if (newline == std::string::npos)
    {
        body.clear();
        return 0;
    }
    const std::string codeText = out.substr(newline + 1);
    if (codeText.size() != 3 ||
        codeText[0] < '0' || codeText[0] > '9' ||
        codeText[1] < '0' || codeText[1] > '9' ||
        codeText[2] < '0' || codeText[2] > '9')
    {
        body = out;
        return 0;
    }
    body = out.substr(0, newline);
    return atoi(codeText.c_str());
}

std::string XmlUnescape(const std::string & text)
{
    std::string out;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] != '&')
        {
            out += text[i];
            continue;
        }
        const size_t semi = text.find(';', i);
        if (semi == std::string::npos || semi - i > 10)
        {
            out += text[i];
            continue;
        }
        const std::string entity = text.substr(i + 1, semi - i - 1);
        if (entity == "amp") { out += '&'; i = semi; }
        else if (entity == "lt") { out += '<'; i = semi; }
        else if (entity == "gt") { out += '>'; i = semi; }
        else if (entity == "quot") { out += '"'; i = semi; }
        else if (entity == "apos") { out += '\''; i = semi; }
        else { out += text[i]; }
    }
    return out;
}

/* First '<tag>content</tag>' anywhere; false when absent. */
bool XmlFind(const std::string & text, const char * tag,
    std::string & content)
{
    const std::string open = std::string("<") + tag + ">";
    const std::string close = std::string("</") + tag + ">";
    const size_t start = text.find(open);
    if (start == std::string::npos)
    {
        return false;
    }
    const size_t body = start + open.size();
    const size_t end = text.find(close, body);
    if (end == std::string::npos)
    {
        return false;
    }
    content = XmlUnescape(text.substr(body, end - body));
    return true;
}

/* All '<tag>...</tag>' inner bodies, in document order. */
std::vector<std::string> XmlAll(const std::string & text, const char * tag)
{
    std::vector<std::string> blocks;
    const std::string open = std::string("<") + tag + ">";
    const std::string close = std::string("</") + tag + ">";
    size_t at = 0;
    while ((at = text.find(open, at)) != std::string::npos)
    {
        const size_t body = at + open.size();
        const size_t end = text.find(close, body);
        if (end == std::string::npos)
        {
            break;
        }
        blocks.push_back(text.substr(body, end - body));
        at = end + close.size();
    }
    return blocks;
}

bool ParseUnsignedDecimal(const std::string & text,
    unsigned long long & value)
{
    if (text.empty())
    {
        return false;
    }
    unsigned long long parsed = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] < '0' || text[i] > '9')
        {
            return false;
        }
        const unsigned digit = static_cast<unsigned>(text[i] - '0');
        if (parsed > (ULLONG_MAX - digit) / 10ULL)
        {
            return false;
        }
        parsed = parsed * 10ULL + digit;
    }
    value = parsed;
    return true;
}

std::string XmlEscape(const std::string & text)
{
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); i++)
    {
        switch (text[i])
        {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&apos;"; break;
        default: out += text[i]; break;
        }
    }
    return out;
}

/* A private per-transfer scratch directory. Multipart parts are copied to
 * disk one at a time because curl's portable -T interface uploads a file,
 * not an arbitrary range of one; keeping them below a user-only directory
 * avoids exposing a copy of the user's data in a shared temporary folder. */
std::string MakeMultipartTempDirectory(std::string & error)
{
    const std::string base = TempDirectory();
    if (base.empty())
    {
        error = "Cannot find a temporary directory for the S3 multipart upload.";
        return std::string();
    }

    static std::atomic<unsigned long long> counter(0);
    for (unsigned int attempt = 0; attempt < 32; attempt++)
    {
        const unsigned long long serial = ++counter;
        const std::string name = "linscp-s3-" +
            std::to_string(static_cast<unsigned long long>(getpid())) + "-" +
            std::to_string(static_cast<unsigned long long>(time(NULL))) + "-" +
            std::to_string(serial);
        const std::string path = JoinLocalPath(base, name);
        LocalFileInfo existing = StatLocal(path);
        if (existing.exists)
        {
            continue;
        }
        std::string createError;
        if (CreatePrivateDirectory(path, createError))
        {
            return path;
        }
        /* Another transfer may have won this name between stat and mkdir;
         * retry that collision, but preserve a real filesystem error. */
        existing = StatLocal(path);
        if (!existing.exists)
        {
            error = "Cannot create a private temporary directory for the S3 "
                "multipart upload: " + createError;
            return std::string();
        }
    }
    error = "Cannot allocate a unique temporary directory for the S3 "
        "multipart upload.";
    return std::string();
}

bool WriteFileRange(const std::string & sourcePath,
    const std::string & targetPath, unsigned long long offset,
    unsigned long long length, std::string & error)
{
    std::ifstream source(sourcePath.c_str(), std::ios::in | std::ios::binary);
    if (!source)
    {
        error = "Cannot open local file '" + sourcePath + "' for reading.";
        return false;
    }
    source.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!source)
    {
        error = "Cannot seek in local file '" + sourcePath + "'.";
        return false;
    }

    std::ofstream target(targetPath.c_str(),
        std::ios::out | std::ios::binary | std::ios::trunc);
    if (!target)
    {
        error = "Cannot create the S3 multipart part file '" + targetPath +
            "'.";
        return false;
    }

    char buffer[1024 * 1024];
    unsigned long long remaining = length;
    while (remaining > 0)
    {
        const size_t wanted = static_cast<size_t>(std::min<unsigned long long>(
            remaining, sizeof(buffer)));
        source.read(buffer, static_cast<std::streamsize>(wanted));
        const std::streamsize got = source.gcount();
        if (got != static_cast<std::streamsize>(wanted))
        {
            target.close();
            remove(targetPath.c_str());
            error = "The local file '" + sourcePath +
                "' changed or ended while preparing an S3 multipart part.";
            return false;
        }
        target.write(buffer, got);
        if (!target)
        {
            target.close();
            remove(targetPath.c_str());
            error = "Cannot write the S3 multipart part file '" + targetPath +
                "'.";
            return false;
        }
        remaining -= static_cast<unsigned long long>(got);
    }
    target.close();
    if (!target)
    {
        remove(targetPath.c_str());
        error = "Cannot finish writing the S3 multipart part file '" +
            targetPath + "'.";
        return false;
    }
    RestrictFileToUser(targetPath);
    return true;
}

std::string ReadLastHeader(const std::string & path, const char * wantedName)
{
    std::ifstream file(path.c_str(), std::ios::in | std::ios::binary);
    if (!file)
    {
        return std::string();
    }
    std::string wanted = ToLower(wantedName);
    std::string value;
    std::string line;
    while (std::getline(file, line))
    {
        if (!line.empty() && line[line.size() - 1] == '\r')
        {
            line.erase(line.size() - 1);
        }
        const size_t colon = line.find(':');
        if (colon == std::string::npos || ToLower(line.substr(0, colon)) != wanted)
        {
            continue;
        }
        size_t first = line.find_first_not_of(" \t", colon + 1);
        value = first == std::string::npos ? std::string() : line.substr(first);
    }
    return value;
}

void RemoveMultipartTempDirectory(const std::string & directory)
{
    if (directory.empty())
    {
        return;
    }
    const std::string part = JoinLocalPath(directory, "part.data");
    const std::string headers = JoinLocalPath(directory, "part.headers");
    const std::string completion = JoinLocalPath(directory, "complete.xml");
    remove(part.c_str());
    remove(headers.c_str());
    remove(completion.c_str());
    std::string ignored;
    RemoveLocalDirectory(directory, ignored);
}

std::string ErrorFromXml(const std::string & body, int httpCode)
{
    std::string code;
    std::string message;
    XmlFind(body, "Code", code);
    XmlFind(body, "Message", message);
    std::string text = "S3 error " + std::to_string(httpCode);
    if (!code.empty())
    {
        text += " (" + code + ")";
    }
    if (!message.empty())
    {
        text += ": " + message;
    }
    return text + ".";
}

/* '2015-08-30T12:36:00.000Z' -> epoch seconds (0 when unparseable). */
unsigned long Iso8601Epoch(const std::string & value)
{
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (sscanf(value.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d",
            &year, &month, &day, &hour, &minute, &second) != 6 ||
        year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 60)
    {
        return 0;
    }
    /* Days since 1970-01-01 (Howard Hinnant's days_from_civil). */
    year -= month <= 2;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(year - era * 400);
    const unsigned doy = static_cast<unsigned>((153 * (month + (month > 2 ?
        -3 : 9)) + 2) / 5 + day - 1);
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const long long days = static_cast<long long>(era) * 146097 +
        static_cast<long long>(doe) - 719468;
    return static_cast<unsigned long>(days * 86400LL +
        hour * 3600LL + minute * 60LL + second);
}

std::string TrailingSlashRemoved(const std::string & path)
{
    std::string out = path;
    while (out.size() > 1 && out[out.size() - 1] == '/')
    {
        out.erase(out.size() - 1);
    }
    return out;
}

/* ---- the request -------------------------------------------------------- */

/*
 * Signs and runs one request. Returns false only when the endpoint
 * could not be reached or answered at the transport level; every HTTP
 * answer, error pages included, comes back in 'response'.
 */
void AppendS3ObjectWriteHeaders(const SessionOptions & options,
    std::vector<std::pair<std::string, std::string> > & headers)
{
    if (!options.s3.storageClass.empty())
    {
        headers.push_back(std::make_pair(std::string("x-amz-storage-class"),
            options.s3.storageClass));
    }
    if (!options.s3.acl.empty())
    {
        headers.push_back(std::make_pair(std::string("x-amz-acl"),
            options.s3.acl));
    }
    if (!options.s3.serverSideEncryption.empty())
    {
        headers.push_back(std::make_pair(
            std::string("x-amz-server-side-encryption"),
            options.s3.serverSideEncryption));
    }
    if (!options.s3.kmsKeyId.empty())
    {
        headers.push_back(std::make_pair(
            std::string("x-amz-server-side-encryption-aws-kms-key-id"),
            options.s3.kmsKeyId));
    }
    for (std::map<std::string, std::string>::const_iterator it =
            options.s3.metadata.begin();
         it != options.s3.metadata.end(); ++it)
    {
        headers.push_back(std::make_pair(
            std::string("x-amz-meta-") + it->first, it->second));
    }
}

bool InvokeCurl(const S3Site & site, const SessionOptions & options,
    const std::string & method, const std::string & encodedPath,
    const std::string & query,
    const std::vector<std::pair<std::string, std::string> > & signedExtras,
    const std::string & payloadHash,
    const std::vector<std::string> & extraArgs,
    const std::string & outFile, S3Response & response,
    std::string & transportError, LscpProgressFn progress = NULL,
    void * progressCtx = NULL, bool upload = false)
{
    std::vector<std::pair<std::string, std::string> > effectiveExtras =
        signedExtras;
    if (options.s3.requestPayer)
    {
        effectiveExtras.push_back(std::make_pair(
            std::string("x-amz-request-payer"), std::string("requester")));
    }
    const unsigned long long now = static_cast<unsigned long long>(time(NULL));
    const s3sig::SignedRequest signed1 = s3sig::Sign(method, encodedPath,
        query, site.authority, effectiveExtras, payloadHash, now, site.region,
        site.accessKey, site.secretKey);

    std::vector<std::string> args;
    args.push_back(CurlExecutable());
    if (progress == NULL)
    {
        args.push_back("-s");
    }
    args.push_back("-S");
    if (progress != NULL)
    {
        args.push_back("--progress-meter");
    }
    /*
     * Deliberately no -f: the HTTP status comes from --write-out and
     * the body keeps the S3 error document, which is how a failure
     * gets a Code and a Message instead of "curl (22)".
     */
    if (options.hostKey == "*")
    {
        args.push_back("--insecure");
    }
    if (options.timeoutSecs > 0)
    {
        args.push_back("--connect-timeout");
        args.push_back(std::to_string(options.timeoutSecs));
    }
    args.push_back("-X");
    args.push_back(method);
    for (size_t i = 0; i < signed1.headers.size(); i++)
    {
        args.push_back("-H");
        args.push_back(signed1.headers[i].first + ": " +
            signed1.headers[i].second);
    }
    args.push_back("-H");
    args.push_back("Authorization: " + signed1.authorization);
    for (size_t i = 0; i < extraArgs.size(); i++)
    {
        args.push_back(extraArgs[i]);
    }
    if (!outFile.empty())
    {
        args.push_back("-o");
        args.push_back(outFile);
    }
    args.push_back("-w");
    args.push_back("\n%{http_code}");
    args.push_back(S3Url(site, encodedPath, query));

    std::string out;
    const int rc = progress != NULL ?
        RunCurlCaptureWithProgress(args, out, response.err, progress,
            progressCtx, upload) :
        RunCapture(args, out, response.err);
    response.curlCode = rc;
    if (rc == -1 && response.err.empty())
    {
        transportError = "Failed to run curl. Install curl (apt install "
            "curl) and make sure it is on PATH.";
        return false;
    }
    if (rc != 0 && IsCurlEndpointUnreachable(rc))
    {
        transportError = response.err;
        if (transportError.empty())
        {
            transportError = "curl error " + std::to_string(rc) + ".";
        }
        return false;
    }
    std::string body;
    response.httpCode = SplitWriteOut(out, body);
    response.out = body;
    return true;
}

/* Reads a file that curl wrote an error document into, then drops it. */
std::string ConsumeErrorFile(const std::string & path, int httpCode)
{
    std::string body;
    FILE * file = fopen(path.c_str(), "rb");
    if (file != NULL)
    {
        char buffer[2048];
        const size_t got = fread(buffer, 1, sizeof(buffer), file);
        fclose(file);
        body.assign(buffer, got);
    }
    remove(path.c_str());
    if (body.empty())
    {
        return "S3 error " + std::to_string(httpCode) + ".";
    }
    return ErrorFromXml(body, httpCode);
}

/* Failure helper: builds the message for an HTTP-level failure. */
std::string HttpFailure(const S3Response & response, const std::string & what)
{
    if (response.httpCode >= 400)
    {
        return ErrorFromXml(response.out, response.httpCode);
    }
    if (!response.err.empty())
    {
        return what + " failed: " + response.err;
    }
    return what + " failed with curl exit code " +
        std::to_string(response.curlCode) + ".";
}

struct UploadedPart
{
    unsigned int number;
    std::string etag;
};

void AbortMultipartUpload(const S3Site & site,
    const SessionOptions & options, const std::string & path,
    const std::string & uploadId)
{
    S3Response ignored;
    std::string ignoredError;
    InvokeCurl(site, options, "DELETE", path,
        "uploadId=" + s3sig::UriEncode(uploadId, false),
        std::vector<std::pair<std::string, std::string> >(), kEmptySha256,
        std::vector<std::string>(), std::string(), ignored, ignoredError);
}

bool WriteCompletionDocument(const std::string & path,
    const std::vector<UploadedPart> & parts, std::string & error)
{
    std::ofstream file(path.c_str(), std::ios::out | std::ios::binary |
        std::ios::trunc);
    if (!file)
    {
        error = "Cannot create the S3 multipart completion document.";
        return false;
    }
    file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<CompleteMultipartUpload>";
    for (size_t i = 0; i < parts.size(); i++)
    {
        file << "<Part><PartNumber>" << parts[i].number
            << "</PartNumber><ETag>" << XmlEscape(parts[i].etag)
            << "</ETag></Part>";
    }
    file << "</CompleteMultipartUpload>";
    file.close();
    if (!file)
    {
        remove(path.c_str());
        error = "Cannot finish writing the S3 multipart completion document.";
        return false;
    }
    RestrictFileToUser(path);
    return true;
}

std::string MultipartResumeStatePath(const S3Site & site,
    const std::string & localPath, const std::string & remotePath)
{
    std::string root = ConfigDirectory();
    if (root.empty())
    {
        root = TempDirectory();
    }
    if (root.empty())
    {
        return std::string();
    }
    std::string dirError;
    const std::string dir = JoinLocalPath(root, "s3-multipart");
    if (!CreatePrivateDirectory(dir, dirError))
    {
        return std::string();
    }
    const std::string key = site.authority + "\n" + remotePath + "\n" + localPath;
    return JoinLocalPath(dir, s3sig::Sha256Hex(key) + ".state");
}

bool LoadMultipartResumeState(const std::string & statePath,
    std::string & uploadId, unsigned long long & fileSize,
    unsigned long & fileMtime, unsigned long long & partSize,
    std::vector<UploadedPart> & parts)
{
    uploadId.clear();
    fileSize = 0;
    fileMtime = 0;
    partSize = 0;
    parts.clear();
    if (statePath.empty())
    {
        return false;
    }
    FILE * file = fopen(statePath.c_str(), "rb");
    if (file == NULL)
    {
        return false;
    }
    char line[2048];
    while (fgets(line, sizeof(line), file) != NULL)
    {
        std::string text = line;
        while (!text.empty() &&
               (text[text.size() - 1] == '\n' || text[text.size() - 1] == '\r'))
        {
            text.erase(text.size() - 1);
        }
        if (text.compare(0, 10, "upload_id=") == 0)
        {
            uploadId = text.substr(10);
        }
        else if (text.compare(0, 10, "file_size=") == 0)
        {
            fileSize = strtoull(text.substr(10).c_str(), NULL, 10);
        }
        else if (text.compare(0, 11, "file_mtime=") == 0)
        {
            fileMtime = strtoul(text.substr(11).c_str(), NULL, 10);
        }
        else if (text.compare(0, 10, "part_size=") == 0)
        {
            partSize = strtoull(text.substr(10).c_str(), NULL, 10);
        }
        else if (text.compare(0, 5, "part=") == 0)
        {
            const std::string rest = text.substr(5);
            const size_t space = rest.find(' ');
            if (space != std::string::npos)
            {
                UploadedPart part;
                part.number = static_cast<unsigned int>(
                    strtoul(rest.substr(0, space).c_str(), NULL, 10));
                part.etag = rest.substr(space + 1);
                if (part.number > 0 && !part.etag.empty())
                {
                    parts.push_back(part);
                }
            }
        }
    }
    fclose(file);
    return !uploadId.empty();
}

void SaveMultipartResumeState(const std::string & statePath,
    const std::string & uploadId, unsigned long long fileSize,
    unsigned long fileMtime, unsigned long long partSize,
    const std::vector<UploadedPart> & parts)
{
    if (statePath.empty() || uploadId.empty())
    {
        return;
    }
    FILE * file = fopen(statePath.c_str(), "wb");
    if (file == NULL)
    {
        return;
    }
    fprintf(file, "upload_id=%s\n", uploadId.c_str());
    fprintf(file, "file_size=%llu\n", fileSize);
    fprintf(file, "file_mtime=%lu\n", fileMtime);
    fprintf(file, "part_size=%llu\n", partSize);
    for (size_t i = 0; i < parts.size(); i++)
    {
        fprintf(file, "part=%u %s\n", parts[i].number, parts[i].etag.c_str());
    }
    fclose(file);
    RestrictFileToUser(statePath);
}

int UploadMultipart(const S3Site & site, const SessionOptions & options,
    const std::string & localPath, const std::string & remotePath,
    unsigned long long fileSize, unsigned long initialMtime,
    LscpProgressFn progress, void * progressCtx,
    unsigned speedKBytesPerSecond, std::string & error)
{
    if (fileSize > kS3MaximumObjectSize)
    {
        error = "S3 objects cannot be larger than 5 TiB.";
        return -1;
    }

    /* Scale the part size up for huge objects, preserving the AWS maximum
     * of 10,000 parts and its minimum of 5 MiB for every non-final part. */
    unsigned long long partSize = kS3MinimumPartSize;
    const unsigned long long requiredPartSize =
        (fileSize + kS3MaximumParts - 1) / kS3MaximumParts;
    if (requiredPartSize > partSize)
    {
        partSize = requiredPartSize;
    }
    const unsigned long long partCount = (fileSize + partSize - 1) / partSize;
    if (partCount == 0 || partCount > kS3MaximumParts)
    {
        error = "The file cannot be represented as a valid S3 multipart "
            "upload (the service permits at most 10,000 parts).";
        return -1;
    }

    std::string bucket;
    std::string key;
    if (!SplitBucketKey(remotePath, bucket, key, error))
    {
        return -1;
    }
    if (key.empty())
    {
        error = "An S3 multipart upload needs an object name below the bucket.";
        return -1;
    }

    const std::string encodedPath = EncodePath(remotePath);
    std::string tempDirectory = MakeMultipartTempDirectory(error);
    if (tempDirectory.empty())
    {
        return -1;
    }
    const std::string partPath = JoinLocalPath(tempDirectory, "part.data");
    const std::string headersPath = JoinLocalPath(tempDirectory, "part.headers");
    const std::string completionPath = JoinLocalPath(tempDirectory, "complete.xml");
    const std::string statePath = MultipartResumeStatePath(site, localPath, remotePath);
    std::string uploadId;
    std::vector<UploadedPart> parts;
    parts.reserve(static_cast<size_t>(partCount));
    bool initiated = false;
    bool completed = false;
    bool abortOnFailure = true;

    std::string savedUploadId;
    unsigned long long savedFileSize = 0;
    unsigned long savedMtime = 0;
    unsigned long long savedPartSize = 0;
    std::vector<UploadedPart> savedParts;
    if (LoadMultipartResumeState(statePath, savedUploadId, savedFileSize,
            savedMtime, savedPartSize, savedParts))
    {
        if (savedFileSize == fileSize && savedMtime == initialMtime &&
            savedPartSize == partSize && !savedParts.empty())
        {
            uploadId = savedUploadId;
            parts = savedParts;
            initiated = true;
        }
        else
        {
            AbortMultipartUpload(site, options, encodedPath, savedUploadId);
            remove(statePath.c_str());
        }
    }

    if (!initiated)
    {
        std::vector<std::pair<std::string, std::string> > initHeaders;
        AppendS3ObjectWriteHeaders(options, initHeaders);
        S3Response response;
        if (!InvokeCurl(site, options, "POST", encodedPath, "uploads",
                initHeaders, kEmptySha256, std::vector<std::string>(),
                std::string(), response, error))
        {
            RemoveMultipartTempDirectory(tempDirectory);
            return -1;
        }
        if (response.httpCode < 200 || response.httpCode >= 300 ||
            response.curlCode != 0)
        {
            error = HttpFailure(response, "Start multipart upload");
            RemoveMultipartTempDirectory(tempDirectory);
            return -1;
        }
        if (!XmlFind(response.out, "UploadId", uploadId) || uploadId.empty())
        {
            error = "The S3 server accepted a multipart upload but returned no "
                "UploadId.";
            RemoveMultipartTempDirectory(tempDirectory);
            return -1;
        }
        initiated = true;
    }

    unsigned long long offset = 0;
    bool ok = true;
    for (unsigned int number = 1; offset < fileSize; number++)
    {
        const unsigned long long length = std::min(partSize, fileSize - offset);
        bool alreadyDone = false;
        for (size_t k = 0; k < parts.size(); k++)
        {
            if (parts[k].number == number)
            {
                alreadyDone = true;
                break;
            }
        }
        if (alreadyDone)
        {
            offset += length;
            if (progress != NULL)
            {
                progress(offset, fileSize, progressCtx);
            }
            continue;
        }
        if (!WriteFileRange(localPath, partPath, offset, length, error))
        {
            ok = false;
            abortOnFailure = parts.empty();
            break;
        }
        remove(headersPath.c_str());

        std::vector<std::string> args;
        args.push_back("-T");
        args.push_back(partPath);
        args.push_back("-D");
        args.push_back(headersPath);
        if (speedKBytesPerSecond > 0)
        {
            args.push_back("--limit-rate");
            args.push_back(std::to_string(speedKBytesPerSecond) + "k");
        }
        const std::string query = "partNumber=" + std::to_string(number) +
            "&uploadId=" + s3sig::UriEncode(uploadId, false);
        S3Response partResponse;
        if (!InvokeCurl(site, options, "PUT", encodedPath, query,
                std::vector<std::pair<std::string, std::string> >(),
                kUnsignedPayload, args, std::string(), partResponse, error))
        {
            ok = false;
            abortOnFailure = parts.empty();
            break;
        }
        if (partResponse.httpCode < 200 || partResponse.httpCode >= 300 ||
            partResponse.curlCode != 0)
        {
            error = HttpFailure(partResponse, "Upload S3 part " +
                std::to_string(number));
            ok = false;
            abortOnFailure = parts.empty();
            break;
        }

        UploadedPart part;
        part.number = number;
        part.etag = ReadLastHeader(headersPath, "ETag");
        if (part.etag.empty())
        {
            error = "The S3 server did not return an ETag for multipart part " +
                std::to_string(number) + ".";
            ok = false;
            abortOnFailure = parts.empty();
            break;
        }
        parts.push_back(part);
        SaveMultipartResumeState(statePath, uploadId, fileSize, initialMtime,
            partSize, parts);
        offset += length;
        if (progress != NULL)
        {
            progress(offset, fileSize, progressCtx);
        }
    }

    if (ok && !WriteCompletionDocument(completionPath, parts, error))
    {
        ok = false;
        abortOnFailure = true;
    }
    if (ok)
    {
        /* Recheck only after writing the small completion document, as close
         * as possible to making the multipart object visible on the server. */
        const LocalFileInfo after = StatLocal(localPath);
        if (!after.exists || !after.isRegular || after.size != fileSize ||
            after.mtime != initialMtime)
        {
            error = "The local file changed while it was being uploaded "
                "to S3; the multipart upload was cancelled.";
            ok = false;
            abortOnFailure = true;
        }
    }
    if (ok)
    {
        abortOnFailure = true;
        std::vector<std::string> args;
        args.push_back("-H");
        args.push_back("Content-Type: application/xml");
        args.push_back("--data-binary");
        args.push_back("@" + completionPath);
        const std::string query = "uploadId=" +
            s3sig::UriEncode(uploadId, false);
        S3Response completeResponse;
        if (!InvokeCurl(site, options, "POST", encodedPath, query,
                std::vector<std::pair<std::string, std::string> >(),
                kUnsignedPayload, args, std::string(), completeResponse,
                error))
        {
            ok = false;
        }
        else if (completeResponse.httpCode < 200 ||
            completeResponse.httpCode >= 300 || completeResponse.curlCode != 0)
        {
            error = HttpFailure(completeResponse, "Complete multipart upload");
            ok = false;
        }
        else
        {
            std::string embeddedError;
            if (XmlFind(completeResponse.out, "Error", embeddedError))
            {
                /* CompleteMultipartUpload may return an error document with
                 * HTTP 200; the body, not just the status, is authoritative. */
                error = ErrorFromXml(embeddedError, completeResponse.httpCode);
                ok = false;
            }
            else
            {
                completed = true;
            }
        }
    }

    if (completed)
    {
        if (!statePath.empty())
        {
            remove(statePath.c_str());
        }
    }
    else if (initiated && abortOnFailure)
    {
        AbortMultipartUpload(site, options, encodedPath, uploadId);
        if (!statePath.empty())
        {
            remove(statePath.c_str());
        }
    }
    RemoveMultipartTempDirectory(tempDirectory);
    return completed ? 0 : -1;
}

int CopyMultipart(const S3Site & site, const SessionOptions & options,
    const std::string & fromPath, const std::string & toPath,
    unsigned long long objectSize, std::string & error)
{
    unsigned long long partSize = kS3MinimumPartSize;
    const unsigned long long requiredPartSize =
        (objectSize + kS3MaximumParts - 1) / kS3MaximumParts;
    if (requiredPartSize > partSize)
    {
        partSize = requiredPartSize;
    }
    const unsigned long long partCount = (objectSize + partSize - 1) / partSize;
    if (partCount == 0 || partCount > kS3MaximumParts)
    {
        error = "The object cannot be represented as a valid S3 multipart copy.";
        return -1;
    }

    const std::string encodedTo = EncodePath(toPath);
    const std::string encodedSource = s3sig::UriEncode(fromPath, true);
    std::string tempDirectory = MakeMultipartTempDirectory(error);
    if (tempDirectory.empty())
    {
        return -1;
    }
    const std::string completionPath = JoinLocalPath(tempDirectory, "complete.xml");

    std::vector<std::pair<std::string, std::string> > initHeaders;
    AppendS3ObjectWriteHeaders(options, initHeaders);
    S3Response initResponse;
    if (!InvokeCurl(site, options, "POST", encodedTo, "uploads",
            initHeaders, kEmptySha256, std::vector<std::string>(),
            std::string(), initResponse, error))
    {
        RemoveMultipartTempDirectory(tempDirectory);
        return -1;
    }
    if (initResponse.httpCode < 200 || initResponse.httpCode >= 300 ||
        initResponse.curlCode != 0)
    {
        error = HttpFailure(initResponse, "Start multipart copy");
        RemoveMultipartTempDirectory(tempDirectory);
        return -1;
    }
    std::string uploadId;
    if (!XmlFind(initResponse.out, "UploadId", uploadId) || uploadId.empty())
    {
        error = "The S3 server accepted a multipart copy but returned no UploadId.";
        RemoveMultipartTempDirectory(tempDirectory);
        return -1;
    }

    std::vector<UploadedPart> parts;
    parts.reserve(static_cast<size_t>(partCount));
    unsigned long long offset = 0;
    bool ok = true;
    for (unsigned int number = 1; offset < objectSize; number++)
    {
        const unsigned long long length = std::min(partSize, objectSize - offset);
        const unsigned long long endByte = offset + length - 1;
        std::vector<std::pair<std::string, std::string> > copyHeaders;
        copyHeaders.push_back(std::make_pair(
            std::string("x-amz-copy-source"), encodedSource));
        copyHeaders.push_back(std::make_pair(
            std::string("x-amz-copy-source-range"),
            "bytes=" + std::to_string(offset) + "-" + std::to_string(endByte)));
        const std::string query = "partNumber=" + std::to_string(number) +
            "&uploadId=" + s3sig::UriEncode(uploadId, false);
        S3Response partResponse;
        if (!InvokeCurl(site, options, "PUT", encodedTo, query,
                copyHeaders, kEmptySha256, std::vector<std::string>(),
                std::string(), partResponse, error))
        {
            ok = false;
            break;
        }
        if (partResponse.httpCode < 200 || partResponse.httpCode >= 300 ||
            partResponse.curlCode != 0)
        {
            error = HttpFailure(partResponse, "Copy S3 part " +
                std::to_string(number));
            ok = false;
            break;
        }
        std::string embeddedError;
        if (XmlFind(partResponse.out, "Error", embeddedError))
        {
            error = ErrorFromXml(embeddedError, partResponse.httpCode);
            ok = false;
            break;
        }
        std::string etag;
        if (!XmlFind(partResponse.out, "ETag", etag) || etag.empty())
        {
            error = "The S3 server did not return an ETag for copied part " +
                std::to_string(number) + ".";
            ok = false;
            break;
        }
        UploadedPart part;
        part.number = number;
        part.etag = etag;
        parts.push_back(part);
        offset += length;
    }

    bool completed = false;
    if (ok && !WriteCompletionDocument(completionPath, parts, error))
    {
        ok = false;
    }
    if (ok)
    {
        std::vector<std::string> args;
        args.push_back("-H");
        args.push_back("Content-Type: application/xml");
        args.push_back("--data-binary");
        args.push_back("@" + completionPath);
        const std::string query = "uploadId=" +
            s3sig::UriEncode(uploadId, false);
        S3Response completeResponse;
        if (!InvokeCurl(site, options, "POST", encodedTo, query,
                std::vector<std::pair<std::string, std::string> >(),
                kUnsignedPayload, args, std::string(), completeResponse,
                error))
        {
            ok = false;
        }
        else if (completeResponse.httpCode < 200 ||
            completeResponse.httpCode >= 300 || completeResponse.curlCode != 0)
        {
            error = HttpFailure(completeResponse, "Complete multipart copy");
            ok = false;
        }
        else
        {
            std::string embeddedError;
            if (XmlFind(completeResponse.out, "Error", embeddedError))
            {
                error = ErrorFromXml(embeddedError, completeResponse.httpCode);
                ok = false;
            }
            else
            {
                completed = true;
            }
        }
    }
    if (!completed)
    {
        AbortMultipartUpload(site, options, encodedTo, uploadId);
    }
    RemoveMultipartTempDirectory(tempDirectory);
    return completed ? 0 : -1;
}

/* ---- listings ----------------------------------------------------------- */

struct S3Entry
{
    std::string name;
    bool isDir;
    unsigned long long size;
    unsigned long mtime; /* 0 = unknown */
};

bool AppendEntry(LscpNames * names, const std::vector<S3Entry> & entries,
    std::string & error)
{
    names->count = static_cast<int>(entries.size());
    if (names->count == 0)
    {
        names->names = NULL;
        return true;
    }
    names->names = static_cast<LscpName *>(
        calloc(names->count, sizeof(LscpName)));
    if (names->names == NULL)
    {
        names->count = 0;
        error = "Out of memory allocating directory entries.";
        return false;
    }
    for (int i = 0; i < names->count; i++)
    {
        names->names[i].filename = DupString(entries[i].name);
        /* Empty longname: Script formats from the attributes, which is
         * also what keeps the columns stable across locales. */
        names->names[i].longname = DupString("");
        names->names[i].attrs.flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
        names->names[i].attrs.permissions = entries[i].isDir ?
            0040755u : 0100644u;
        names->names[i].attrs.size = entries[i].size;
        if (entries[i].mtime != 0)
        {
            names->names[i].attrs.flags |= LSCP_ATTR_ACMODTIME;
            names->names[i].attrs.atime = entries[i].mtime;
            names->names[i].attrs.mtime = entries[i].mtime;
        }
    }
    return true;
}

bool ListBuckets(const S3Site & site, const SessionOptions & options,
    LscpNames * names, std::string & error)
{
    S3Response response;
    if (!InvokeCurl(site, options, "GET", "/", std::string(),
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(), std::string(),
            response, error))
    {
        return false;
    }
    if (response.httpCode >= 400 || response.curlCode != 0 ||
        response.httpCode == 0)
    {
        error = HttpFailure(response, "ListBuckets");
        return false;
    }
    std::vector<S3Entry> entries;
    const std::vector<std::string> buckets =
        XmlAll(response.out, "Bucket");
    for (size_t i = 0; i < buckets.size(); i++)
    {
        std::string name;
        if (!XmlFind(buckets[i], "Name", name) || name.empty())
        {
            continue;
        }
        S3Entry entry;
        entry.name = name;
        entry.isDir = true;
        entry.size = 0;
        std::string created;
        entry.mtime = XmlFind(buckets[i], "CreationDate", created) ?
            Iso8601Epoch(created) : 0;
        entries.push_back(entry);
    }
    return AppendEntry(names, entries, error);
}

bool ListObjects(const S3Site & site, const SessionOptions & options,
    const std::string & bucket, const std::string & prefixRaw,
    LscpNames * names, std::string & error)
{
    const std::string prefix = prefixRaw;
    std::string query = "list-type=2&delimiter=%2F&prefix=" +
        s3sig::UriEncode(prefix, false);
    std::vector<S3Entry> entries;
    std::map<std::string, size_t> seen;
    std::string continuation;
    std::set<std::string> seenContinuationTokens;
    bool listedAll = false;
    const std::string bucketPath = "/" + s3sig::UriEncode(bucket, false);

    for (int page = 0; page < 1000; page++)
    {
        std::string pageQuery = query;
        if (!continuation.empty())
        {
            pageQuery += "&continuation-token=" +
                s3sig::UriEncode(continuation, false);
        }
        S3Response response;
        if (!InvokeCurl(site, options, "GET", bucketPath, pageQuery,
                std::vector<std::pair<std::string, std::string> >(),
                kEmptySha256, std::vector<std::string>(), std::string(),
                response, error))
        {
            return false;
        }
        if (response.httpCode >= 400 || response.curlCode != 0 ||
            response.httpCode == 0)
        {
            error = HttpFailure(response, "ListObjects");
            return false;
        }

        const std::vector<std::string> contents =
            XmlAll(response.out, "Contents");
        for (size_t i = 0; i < contents.size(); i++)
        {
            std::string key;
            if (!XmlFind(contents[i], "Key", key) || key.empty())
            {
                continue;
            }
            if (StartsWith(key, prefix))
            {
                const std::string relative = key.substr(prefix.size());
                if (relative.empty() || relative == ".")
                {
                    continue; /* the prefix itself or its marker */
                }
                if (relative.find('/') != std::string::npos ||
                    EndsWith(relative, "/"))
                {
                    /* Defensive: a server that ignored the delimiter. */
                    continue;
                }
                if (seen.count(relative) != 0)
                {
                    continue;
                }
                S3Entry entry;
                entry.name = relative;
                entry.isDir = false;
                entry.size = 0;
                std::string sizeText;
                if (XmlFind(contents[i], "Size", sizeText))
                {
                    entry.size = strtoull(sizeText.c_str(), NULL, 10);
                }
                std::string modified;
                entry.mtime = XmlFind(contents[i], "LastModified", modified) ?
                    Iso8601Epoch(modified) : 0;
                seen[relative] = entries.size();
                entries.push_back(entry);
            }
        }

        const std::vector<std::string> prefixes =
            XmlAll(response.out, "CommonPrefixes");
        for (size_t i = 0; i < prefixes.size(); i++)
        {
            std::string full;
            if (!XmlFind(prefixes[i], "Prefix", full) || full.empty() ||
                !StartsWith(full, prefix))
            {
                continue;
            }
            std::string relative = full.substr(prefix.size());
            while (!relative.empty() && relative[relative.size() - 1] == '/')
            {
                relative.erase(relative.size() - 1);
            }
            if (relative.empty() || relative.find('/') != std::string::npos)
            {
                continue;
            }
            std::map<std::string, size_t>::iterator at =
                seen.find(relative);
            if (at != seen.end())
            {
                /* A marker object and a prefix with the same name are
                 * one directory to the user; the directory wins. */
                entries[at->second].isDir = true;
                entries[at->second].size = 0;
                continue;
            }
            S3Entry entry;
            entry.name = relative;
            entry.isDir = true;
            entry.size = 0;
            entry.mtime = 0;
            seen[relative] = entries.size();
            entries.push_back(entry);
        }

        std::string truncated;
        if (!XmlFind(response.out, "IsTruncated", truncated))
        {
            error = "The S3 ListObjects response did not say whether it was "
                "truncated.";
            return false;
        }
        if (truncated == "false")
        {
            listedAll = true;
            break;
        }
        if (truncated != "true")
        {
            error = "The S3 ListObjects response has an invalid IsTruncated "
                "value.";
            return false;
        }
        std::string nextContinuation;
        if (!XmlFind(response.out, "NextContinuationToken", nextContinuation) ||
            nextContinuation.empty())
        {
            error = "The S3 ListObjects response is truncated but has no "
                "continuation token; refusing to return an incomplete listing.";
            return false;
        }
        if (!seenContinuationTokens.insert(nextContinuation).second)
        {
            error = "The S3 ListObjects response repeated a continuation "
                "token; refusing to loop or return an incomplete listing.";
            return false;
        }
        continuation.swap(nextContinuation);
    }
    if (!listedAll)
    {
        error = "The S3 ListObjects response exceeded 1000 pages; refusing "
            "to return an incomplete listing.";
        return false;
    }

    return AppendEntry(names, entries, error);
}

bool ListObjectVersions(const S3Site & site, const SessionOptions & options,
    const std::string & bucket, const std::string & prefix,
    bool exactKey, std::vector<S3ObjectVersion> & versions,
    std::string & error)
{
    const std::string bucketPath = "/" + s3sig::UriEncode(bucket, false);
    std::string keyMarker;
    std::string versionIdMarker;
    std::set<std::pair<std::string, std::string> > seenMarkers;
    std::vector<S3ObjectVersion> gathered;
    bool listedAll = false;

    /* AWS returns at most 1000 records per page. The hard limit prevents a
     * malicious or broken endpoint from making us loop forever or accumulating
     * an unbounded history in memory; reaching it is an error, never a
     * successful partial listing. */
    for (unsigned int page = 0; page < 1000; page++)
    {
        std::string query = "versions=&prefix=" +
            s3sig::UriEncode(prefix, false);
        if (!keyMarker.empty())
        {
            query += "&key-marker=" + s3sig::UriEncode(keyMarker, false);
        }
        if (!versionIdMarker.empty())
        {
            query += "&version-id-marker=" +
                s3sig::UriEncode(versionIdMarker, false);
        }

        S3Response response;
        if (!InvokeCurl(site, options, "GET", bucketPath, query,
                std::vector<std::pair<std::string, std::string> >(),
                kEmptySha256, std::vector<std::string>(), std::string(),
                response, error))
        {
            return false;
        }
        if (response.httpCode >= 400 || response.curlCode != 0 ||
            response.httpCode == 0)
        {
            error = HttpFailure(response, "ListObjectVersions");
            return false;
        }

        size_t at = 0;
        while (true)
        {
            const size_t versionAt = response.out.find("<Version>", at);
            const size_t markerAt = response.out.find("<DeleteMarker>", at);
            if (versionAt == std::string::npos && markerAt == std::string::npos)
            {
                break;
            }
            const bool deleteMarker = markerAt != std::string::npos &&
                (versionAt == std::string::npos || markerAt < versionAt);
            const char * tag = deleteMarker ? "DeleteMarker" : "Version";
            const size_t start = deleteMarker ? markerAt : versionAt;
            const std::string open = std::string("<") + tag + ">";
            const std::string close = std::string("</") + tag + ">";
            const size_t bodyStart = start + open.size();
            const size_t end = response.out.find(close, bodyStart);
            if (end == std::string::npos)
            {
                error = "The S3 ListObjectVersions response contains an "
                    "unfinished " + std::string(tag) + " record.";
                return false;
            }
            const std::string block = response.out.substr(bodyStart,
                end - bodyStart);
            S3ObjectVersion item;
            item.isDeleteMarker = deleteMarker;
            std::string latest;
            std::string modified;
            if (!XmlFind(block, "Key", item.key) || item.key.empty() ||
                !XmlFind(block, "VersionId", item.versionId) ||
                item.versionId.empty() ||
                !XmlFind(block, "IsLatest", latest) ||
                !XmlFind(block, "LastModified", modified))
            {
                error = "The S3 ListObjectVersions response contains a "
                    "record without its key, version ID, latest flag or "
                    "modification time.";
                return false;
            }
            if (latest != "true" && latest != "false")
            {
                error = "The S3 ListObjectVersions response contains an "
                    "invalid IsLatest value.";
                return false;
            }
            item.isLatest = latest == "true";
            item.mtime = Iso8601Epoch(modified);
            if (!deleteMarker)
            {
                std::string sizeText;
                if (!XmlFind(block, "Size", sizeText) ||
                    !ParseUnsignedDecimal(sizeText, item.size))
                {
                    error = "The S3 ListObjectVersions response contains an "
                        "invalid object size.";
                    return false;
                }
            }
            if (!exactKey || item.key == prefix)
            {
                gathered.push_back(item);
            }
            at = end + close.size();
        }

        std::string truncated;
        if (!XmlFind(response.out, "IsTruncated", truncated))
        {
            error = "The S3 ListObjectVersions response did not say whether "
                "it was truncated.";
            return false;
        }
        if (truncated == "false")
        {
            listedAll = true;
            break;
        }
        if (truncated != "true")
        {
            error = "The S3 ListObjectVersions response has an invalid "
                "IsTruncated value.";
            return false;
        }

        std::string nextKeyMarker;
        if (!XmlFind(response.out, "NextKeyMarker", nextKeyMarker) ||
            nextKeyMarker.empty())
        {
            error = "The S3 ListObjectVersions response is truncated but "
                "has no next key marker; refusing to return an incomplete "
                "listing.";
            return false;
        }
        std::string nextVersionMarker;
        if (!XmlFind(response.out, "NextVersionIdMarker", nextVersionMarker) ||
            nextVersionMarker.empty())
        {
            error = "The S3 ListObjectVersions response is truncated but "
                "has no next version ID marker; refusing to return an "
                "incomplete listing.";
            return false;
        }
        const std::pair<std::string, std::string> marker(nextKeyMarker,
            nextVersionMarker);
        if (marker == std::make_pair(keyMarker, versionIdMarker) ||
            !seenMarkers.insert(marker).second)
        {
            error = "The S3 ListObjectVersions response repeated its "
                "pagination marker; refusing to loop or return an "
                "incomplete listing.";
            return false;
        }
        keyMarker.swap(nextKeyMarker);
        versionIdMarker.swap(nextVersionMarker);
    }

    if (!listedAll)
    {
        error = "The S3 ListObjectVersions response exceeded 1000 pages; "
            "refusing to return an incomplete listing.";
        return false;
    }
    versions.swap(gathered);
    return true;
}

/* ---- shared request blocks --------------------------------------------- */

/* Runs a signed request and translates the outcome into one of the
 * stat codes, filling 'attrs' when the target exists. */
int StatRequest(const S3Site & site, const SessionOptions & options,
    const std::string & path, LscpAttrs * attrs, std::string & error,
    const std::string & query = std::string(), bool * deleteMarker = NULL)
{
    if (deleteMarker != NULL)
    {
        *deleteMarker = false;
    }
    S3Response response;
    if (!InvokeCurl(site, options, "HEAD", EncodePath(path), query,
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(1, "-I"),
            std::string(), response, error))
    {
        return LSCP_SFTP_STAT_ERROR;
    }
    if (response.curlCode != 0)
    {
        error = HttpFailure(response, "Stat");
        return LSCP_SFTP_STAT_ERROR;
    }
    if (response.httpCode == 0)
    {
        error = "The S3 endpoint returned no status for '" + path + "'.";
        return LSCP_SFTP_STAT_ERROR;
    }
    if (response.httpCode == 404)
    {
        return LSCP_SFTP_STAT_MISSING;
    }
    if (response.httpCode >= 400)
    {
        const std::string headers = ToLower(response.out);
        if (deleteMarker != NULL && response.httpCode == 405 &&
            headers.find("x-amz-delete-marker: true") != std::string::npos)
        {
            *deleteMarker = true;
        }
        error = ErrorFromXml(response.out, response.httpCode);
        return LSCP_SFTP_STAT_ERROR;
    }
    if (attrs != NULL)
    {
        attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
        attrs->permissions = EndsWith(path, "/") ? 0040755u : 0100644u;
        attrs->size = 0;
        attrs->atime = 0;
        attrs->mtime = 0;
        /* The HEAD header block, lowercased for the search. */
        const std::string headers = ToLower(response.out);
        const size_t length = headers.find("content-length:");
        if (length != std::string::npos)
        {
            attrs->size = strtoull(headers.c_str() + length +
                strlen("content-length:"), NULL, 10);
        }
        const size_t modified = headers.find("last-modified:");
        if (modified != std::string::npos)
        {
            const size_t value = headers.find_first_not_of(" \t\r",
                modified + strlen("last-modified:"));
            if (value != std::string::npos)
            {
                const unsigned long stamp =
                    ParseHttpDate(response.out.substr(value));
                if (stamp != 0)
                {
                    attrs->flags |= LSCP_ATTR_ACMODTIME;
                    attrs->atime = stamp;
                    attrs->mtime = stamp;
                }
            }
        }
    }
    return LSCP_SFTP_STAT_EXISTS;
}

/* True when there is something under 'prefix' besides the marker of
 * 'prefix' itself. Any list failure is reported as an error. */
bool PrefixHasChildren(const S3Site & site, const SessionOptions & options,
    const std::string & bucket, const std::string & prefix,
    bool & hasChildren, std::string & error)
{
    hasChildren = false;
    const std::string query = "list-type=2&delimiter=%2F&max-keys=11" +
        std::string("&prefix=") + s3sig::UriEncode(prefix, false);
    S3Response response;
    if (!InvokeCurl(site, options, "GET",
            "/" + s3sig::UriEncode(bucket, false), query,
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(), std::string(),
            response, error))
    {
        return false;
    }
    if (response.httpCode >= 400 || response.curlCode != 0 ||
        response.httpCode == 0)
    {
        error = HttpFailure(response, "ListObjects");
        return false;
    }
    const std::vector<std::string> contents =
        XmlAll(response.out, "Contents");
    for (size_t i = 0; i < contents.size(); i++)
    {
        std::string key;
        if (XmlFind(contents[i], "Key", key) && !key.empty() && key != prefix)
        {
            hasChildren = true;
            return true;
        }
    }
    if (!XmlAll(response.out, "CommonPrefixes").empty())
    {
        hasChildren = true;
        return true;
    }
    std::string truncated;
    if (XmlFind(response.out, "IsTruncated", truncated) &&
        truncated == "true")
    {
        hasChildren = true;
    }
    return true;
}

} // namespace

/* ---- public entry points ------------------------------------------------ */

bool S3Client::List(const SessionOptions & options,
    const std::string & remotePath, LscpNames * names, std::string & error)
{
    if (names == NULL)
    {
        error = "Null output pointer.";
        return false;
    }
    names->count = 0;
    names->names = NULL;

    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return false;
    }

    /* Directories are prefixes: the listing path always ends in '/'
     * (the same normalization the curl protocols do), so '/bucket'
     * lists the bucket and '/bucket/docs' only things under 'docs/'. */
    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    if (path.size() > 1 && path[path.size() - 1] != '/')
    {
        path += "/";
    }
    if (path == "/")
    {
        return ListBuckets(site, options, names, error);
    }
    std::string bucket;
    std::string key;
    if (!SplitBucketKey(path, bucket, key, error))
    {
        return false;
    }
    return ListObjects(site, options, bucket, key, names, error);
}

bool S3Client::ListVersions(const SessionOptions & options,
    const std::string & remotePath, std::vector<S3ObjectVersion> & versions,
    std::string & error)
{
    error.clear();
    versions.clear();
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return false;
    }
    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    std::string bucket;
    std::string key;
    if (!SplitBucketKey(path, bucket, key, error))
    {
        return false;
    }
    const bool exactKey = !key.empty() && !EndsWith(key, "/");
    return ListObjectVersions(site, options, bucket, key, exactKey,
        versions, error);
}

int S3Client::Stat(const SessionOptions & options,
    const std::string & remotePath, LscpAttrs * attrs, std::string & error)
{
    if (attrs != NULL)
    {
        memset(attrs, 0, sizeof(*attrs));
    }
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return LSCP_SFTP_STAT_ERROR;
    }
    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    if (path == "/")
    {
        if (attrs != NULL)
        {
            attrs->flags = LSCP_ATTR_PERMISSIONS;
            attrs->permissions = 0040755;
        }
        return LSCP_SFTP_STAT_EXISTS;
    }

    std::string bucket;
    std::string key;
    if (!SplitBucketKey(path, bucket, key, error))
    {
        return LSCP_SFTP_STAT_ERROR;
    }

    const int direct = StatRequest(site, options, path, attrs, error);
    if (direct == LSCP_SFTP_STAT_EXISTS && key.empty() && attrs != NULL)
    {
        /* The bucket root is a directory, whatever its HEAD says. */
        attrs->permissions = 0040755;
    }
    if (direct != LSCP_SFTP_STAT_MISSING || key.empty() ||
        EndsWith(key, "/"))
    {
        /* The bucket root and marker paths have no second form. */
        return direct;
    }
    /* 'dir' as a file name may still be a directory: try its marker. */
    error.clear();
    const int marker = StatRequest(site, options, path + "/", attrs, error);
    if (marker == LSCP_SFTP_STAT_EXISTS)
    {
        return LSCP_SFTP_STAT_EXISTS;
    }
    if (marker == LSCP_SFTP_STAT_ERROR)
    {
        return LSCP_SFTP_STAT_ERROR;
    }
    error.clear();
    return LSCP_SFTP_STAT_MISSING;
}

int S3Client::StatVersion(const SessionOptions & options,
    const std::string & remotePath, const std::string & versionId,
    LscpAttrs * attrs, std::string & error)
{
    error.clear();
    if (attrs != NULL)
    {
        memset(attrs, 0, sizeof(*attrs));
    }
    if (versionId.empty())
    {
        error = "An S3 version ID cannot be empty.";
        return LSCP_SFTP_STAT_ERROR;
    }
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return LSCP_SFTP_STAT_ERROR;
    }
    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    std::string bucket;
    std::string key;
    if (!SplitBucketKey(path, bucket, key, error) || key.empty() ||
        EndsWith(key, "/"))
    {
        if (error.empty())
        {
            error = "'" + remotePath + "' is not an S3 object name.";
        }
        return LSCP_SFTP_STAT_ERROR;
    }
    bool deleteMarker = false;
    const std::string query = "versionId=" +
        s3sig::UriEncode(versionId, false);
    const int result = StatRequest(site, options, path, attrs, error, query,
        &deleteMarker);
    if (deleteMarker)
    {
        error = "S3 version '" + versionId + "' of '" + path +
            "' is a delete marker, not a downloadable object.";
        return LSCP_SFTP_STAT_ERROR;
    }
    if (result == LSCP_SFTP_STAT_MISSING)
    {
        error = "S3 object version '" + versionId + "' of '" + path +
            "' does not exist.";
    }
    return result;
}

bool S3Client::CheckEndpoint(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    (void)remotePath;
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return false;
    }
    S3Response response;
    if (!InvokeCurl(site, options, "GET", "/", std::string(),
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(), std::string(),
            response, error))
    {
        return false;
    }
    if (response.httpCode == 0 && response.curlCode != 0)
    {
        error = HttpFailure(response, "Opening the S3 endpoint");
        return false;
    }
    if (response.httpCode == 403)
    {
        std::string code;
        XmlFind(response.out, "Code", code);
        if (code == "SignatureDoesNotMatch" ||
            code == "InvalidAccessKeyId" ||
            code == "ExpiredToken" || code == "InvalidToken")
        {
            /* Credentials the service refuses: there is no session. */
            error = ErrorFromXml(response.out, response.httpCode);
            return false;
        }
        /* Otherwise the credentials are good enough and ListBuckets
         * is merely not permitted - a bucket-scoped policy, which is
         * normal. The server answered; that is the connection. */
    }
    if (response.httpCode >= 500)
    {
        error = ErrorFromXml(response.out, response.httpCode);
        return false;
    }
    return true;
}

int S3Client::Get(const SessionOptions & options,
    const std::string & remotePath, const std::string & localPath,
    unsigned long long resumeOffset, bool preserveTime,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx,
    std::string & error, unsigned speedKBytesPerSecond,
    const std::string & versionId)
{
    error.clear();
    if (size != NULL)
    {
        *size = 0;
    }
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    if (remotePath.empty() || remotePath[0] != '/' ||
        (remotePath.size() > 1 && remotePath[remotePath.size() - 1] == '/'))
    {
        error = "'" + remotePath + "' is not an object name (S3 downloads "
            "objects, not prefixes).";
        return -1;
    }

    std::vector<std::string> extraArgs;
    if (resumeOffset > 0)
    {
        /* curl turns this into a Range header; S3 answers 206 and curl
         * stitches. The Range itself is not signed, which SigV4
         * allows: only what we send as canonical headers must be. */
        extraArgs.push_back("-C");
        extraArgs.push_back(std::to_string(resumeOffset));
    }
    if (preserveTime)
    {
        /* Last-Modified of the object onto the local file. */
        extraArgs.push_back("-R");
    }
    if (speedKBytesPerSecond > 0)
    {
        extraArgs.push_back("--limit-rate");
        extraArgs.push_back(std::to_string(speedKBytesPerSecond) + "k");
    }

    const std::string query = versionId.empty() ? std::string() :
        "versionId=" + s3sig::UriEncode(versionId, false);
    S3Response response;
    if (!InvokeCurl(site, options, "GET", EncodePath(remotePath),
            query,
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, extraArgs, localPath, response, error,
            progress, progressCtx, false))
    {
        return -1;
    }
    if (response.httpCode >= 400)
    {
        error = ConsumeErrorFile(localPath, response.httpCode);
        return -1;
    }
    if (response.curlCode != 0 || response.httpCode == 0)
    {
        error = HttpFailure(response, "Download");
        return -1;
    }

    const LocalFileInfo info = StatLocal(localPath);
    if (info.exists && progress != NULL)
    {
        progress(info.size, info.size, progressCtx);
    }
    if (info.exists && size != NULL)
    {
        *size = info.size;
    }
    return 0;
}

int S3Client::Put(const SessionOptions & options,
    const std::string & localPath, const std::string & remotePath,
    int permissions, unsigned long long resumeOffset, bool preserveTime,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx,
    std::string & error, unsigned speedKBytesPerSecond)
{
    (void)permissions; /* S3 has no POSIX modes to set. */
    (void)preserveTime; /* object times are server-side (Last-Modified). */
    /* A prior .filepart object cannot be byte-appended to an S3 object.
     * Multipart uploads below still restart from the first part; they never
     * splice a remote object onto the local source. */
    (void)resumeOffset;
    if (size != NULL)
    {
        *size = 0;
    }
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    if (remotePath.empty() || remotePath[0] != '/')
    {
        error = "The remote path '" + remotePath + "' is not absolute.";
        return -1;
    }

    const LocalFileInfo info = StatLocal(localPath);
    if (info.exists && info.isRegular &&
        info.size > kS3MultipartThreshold)
    {
        if (UploadMultipart(site, options, localPath, remotePath, info.size,
                info.mtime, progress, progressCtx, speedKBytesPerSecond,
                error) != 0)
        {
            return -1;
        }
        if (size != NULL)
        {
            *size = info.size;
        }
        return 0;
    }

    std::vector<std::string> extraArgs;
    extraArgs.push_back("-T");
    extraArgs.push_back(localPath);
    if (speedKBytesPerSecond > 0)
    {
        extraArgs.push_back("--limit-rate");
        extraArgs.push_back(std::to_string(speedKBytesPerSecond) + "k");
    }

    std::vector<std::pair<std::string, std::string> > putHeaders;
    AppendS3ObjectWriteHeaders(options, putHeaders);
    S3Response response;
    if (!InvokeCurl(site, options, "PUT", EncodePath(remotePath),
            std::string(), putHeaders,
            kUnsignedPayload, extraArgs, std::string(), response, error,
            progress, progressCtx, true))
    {
        return -1;
    }
    if (response.httpCode < 200 || response.httpCode >= 300 ||
        response.curlCode != 0)
    {
        error = HttpFailure(response, "Upload");
        return -1;
    }

    if (info.exists && size != NULL)
    {
        *size = info.size;
    }
    if (progress != NULL && info.exists)
    {
        progress(info.size, info.size, progressCtx);
    }
    return 0;
}

int S3Client::Remove(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    S3Response response;
    if (!InvokeCurl(site, options, "DELETE", EncodePath(remotePath),
            std::string(),
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(), std::string(),
            response, error))
    {
        return -1;
    }
    if (response.httpCode == 404)
    {
        error = "No such file or directory. " +
            ErrorFromXml(response.out, response.httpCode);
        return -1;
    }
    if (response.httpCode < 200 || response.httpCode >= 300 ||
        response.curlCode != 0)
    {
        error = HttpFailure(response, "Remove");
        return -1;
    }
    return 0;
}

int S3Client::RemoveVersion(const SessionOptions & options,
    const std::string & remotePath, const std::string & versionId,
    std::string & error)
{
    error.clear();
    if (versionId.empty())
    {
        error = "An S3 version ID cannot be empty.";
        return -1;
    }
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    std::string bucket;
    std::string key;
    if (!SplitBucketKey(path, bucket, key, error) || key.empty() ||
        EndsWith(key, "/"))
    {
        if (error.empty())
        {
            error = "'" + remotePath + "' is not an S3 object name.";
        }
        return -1;
    }
    const std::string query = "versionId=" +
        s3sig::UriEncode(versionId, false);
    S3Response response;
    if (!InvokeCurl(site, options, "DELETE", EncodePath(path), query,
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(), std::string(),
            response, error))
    {
        return -1;
    }
    if (response.httpCode < 200 || response.httpCode >= 300 ||
        response.curlCode != 0)
    {
        error = HttpFailure(response, "Remove S3 version");
        return -1;
    }
    return 0;
}

int S3Client::RemoveDir(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    path = TrailingSlashRemoved(path);
    std::string bucket;
    std::string key;
    if (!SplitBucketKey(path, bucket, key, error))
    {
        return -1;
    }
    if (key.empty())
    {
        error = "The bucket itself cannot be removed with rmdir; use "
            "'rm -r' on its contents (or the S3 console).";
        return -1;
    }
    const std::string prefix = key + "/";
    bool hasChildren = false;
    if (!PrefixHasChildren(site, options, bucket, prefix, hasChildren,
            error))
    {
        return -1;
    }
    if (hasChildren)
    {
        error = "The directory is not empty.";
        return -1;
    }
    S3Response response;
    if (!InvokeCurl(site, options, "DELETE", EncodePath(prefix),
            std::string(),
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(), std::string(),
            response, error))
    {
        return -1;
    }
    if (response.httpCode == 404)
    {
        /* A virtual directory: children could not have existed (checked
         * above), so there is nothing to delete and nothing is wrong. */
        return 0;
    }
    if (response.httpCode < 200 || response.httpCode >= 300 ||
        response.curlCode != 0)
    {
        error = HttpFailure(response, "Remove directory");
        return -1;
    }
    return 0;
}

int S3Client::MakeDir(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    path = TrailingSlashRemoved(path);
    std::string bucket;
    std::string key;
    if (!SplitBucketKey(path, bucket, key, error))
    {
        return -1;
    }
    std::string probeError;
    if (key.empty())
    {
        /* '/name' with nothing under it: creating a bucket, which is a
         * PUT of the bucket itself (S3 creates it when it does not
         * exist yet). */
        const int bucketState = StatRequest(site, options, path, NULL,
            probeError);
        if (bucketState == LSCP_SFTP_STAT_EXISTS)
        {
            error = "Cannot create the directory '" + path +
                "': that name already exists.";
            return -1;
        }
        if (bucketState == LSCP_SFTP_STAT_ERROR)
        {
            error = probeError;
            return -1;
        }
        std::vector<std::string> bucketArgs;
        bucketArgs.push_back("-d");
        bucketArgs.push_back("");
        S3Response bucketPut;
        if (!InvokeCurl(site, options, "PUT", EncodePath(path),
                std::string(),
                std::vector<std::pair<std::string, std::string> >(),
                kEmptySha256, bucketArgs, std::string(), bucketPut, error))
        {
            return -1;
        }
        if (bucketPut.httpCode < 200 || bucketPut.httpCode >= 300 ||
            bucketPut.curlCode != 0)
        {
            error = HttpFailure(bucketPut, "Create bucket");
            return -1;
        }
        return 0;
    }

    /* Refuse to turn an existing file (or directory) into a marker. */
    const int direct = StatRequest(site, options, path, NULL, probeError);
    if (direct == LSCP_SFTP_STAT_EXISTS)
    {
        error = "Cannot create the directory '" + path +
            "': that name already exists.";
        return -1;
    }
    if (direct == LSCP_SFTP_STAT_ERROR)
    {
        error = probeError;
        return -1;
    }
    const int marker = StatRequest(site, options, path + "/", NULL,
        probeError);
    if (marker == LSCP_SFTP_STAT_EXISTS)
    {
        error = "Cannot create the directory '" + path +
            "': that name already exists.";
        return -1;
    }
    if (marker == LSCP_SFTP_STAT_ERROR)
    {
        error = probeError;
        return -1;
    }

    /* The marker: a zero-byte object whose key ends in '/'. */
    std::vector<std::string> extraArgs;
    extraArgs.push_back("-d");
    extraArgs.push_back("");
    S3Response response;
    if (!InvokeCurl(site, options, "PUT", EncodePath(path) + "/",
            std::string(),
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, extraArgs, std::string(), response, error))
    {
        return -1;
    }
    if (response.httpCode < 200 || response.httpCode >= 300 ||
        response.curlCode != 0)
    {
        error = HttpFailure(response, "Create directory");
        return -1;
    }
    return 0;
}

int S3Client::Copy(const SessionOptions & options,
    const std::string & fromPath, const std::string & toPath,
    std::string & error)
{
    error.clear();
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    if (fromPath.empty() || fromPath[0] != '/' || toPath.empty() ||
        toPath[0] != '/')
    {
        error = "S3 copy needs absolute paths.";
        return -1;
    }

    LscpAttrs sourceAttrs = {};
    std::string statError;
    if (!EndsWith(fromPath, ".filepart") &&
        Stat(options, fromPath, &sourceAttrs, statError) == LSCP_SFTP_STAT_EXISTS &&
        (sourceAttrs.flags & LSCP_ATTR_SIZE) != 0 &&
        sourceAttrs.size > kS3MultipartThreshold)
    {
        return CopyMultipart(site, options, fromPath, toPath,
            sourceAttrs.size, error);
    }

    /* CopyObject is a PUT to the destination with the source in
     * x-amz-copy-source (which is signed like every x-amz-* header). */
    std::vector<std::pair<std::string, std::string> > signed1;
    signed1.push_back(std::make_pair("x-amz-copy-source",
        s3sig::UriEncode(fromPath, true)));
    AppendS3ObjectWriteHeaders(options, signed1);
    S3Response response;
    if (!InvokeCurl(site, options, "PUT", EncodePath(toPath), std::string(),
            signed1, kUnsignedPayload, std::vector<std::string>(),
            std::string(), response, error))
    {
        return -1;
    }
    if (response.httpCode < 200 || response.httpCode >= 300 ||
        response.curlCode != 0)
    {
        error = HttpFailure(response, "Copy");
        return -1;
    }
    std::string embeddedError;
    if (XmlFind(response.out, "Error", embeddedError))
    {
        /* CopyObject can return an error inside an otherwise-200 response. */
        error = ErrorFromXml(embeddedError, response.httpCode);
        return -1;
    }
    return 0;
}

int S3Client::Move(const SessionOptions & options,
    const std::string & fromPath, const std::string & toPath,
    std::string & error)
{
    if (Copy(options, fromPath, toPath, error) != 0)
    {
        error = "Rename (copy phase) failed: " + error;
        return -1;
    }

    S3Response delete1;
    const S3Site site = S3SiteOf(options);
    if (!site.ok)
    {
        error = site.error;
        return -1;
    }
    if (!InvokeCurl(site, options, "DELETE", EncodePath(fromPath),
            std::string(),
            std::vector<std::pair<std::string, std::string> >(),
            kEmptySha256, std::vector<std::string>(), std::string(),
            delete1, error))
    {
        error = "The copy to '" + toPath + "' succeeded, but removing the "
            "source failed: " + error;
        return -1;
    }
    if (delete1.httpCode == 404)
    {
        return 0; /* already gone; the destination holds the data */
    }
    if (delete1.httpCode < 200 || delete1.httpCode >= 300 ||
        delete1.curlCode != 0)
    {
        error = "The copy to '" + toPath + "' succeeded, but removing the "
            "source failed: " + HttpFailure(delete1, "Remove");
        return -1;
    }
    return 0;
}

} // namespace linscp
