#include "ProtocolClient.h"
#include "FtpClient.h"
#include "ScpClient.h"
#include "ListingParse.h"
#include "S3Client.h"
#include "S3SigV4.h"
#include "LocalFs.h"
#include "PathUtil.h"
#include "Platform.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

namespace linscp {

/* The lock token this session holds for a path, or an empty string: the
 * If header that makes the server enforce the lock. */
std::string DavTokenFor(const SessionOptions & options,
    const std::string & remotePath)
{
    std::map<std::string, std::string>::const_iterator found =
        options.davLocks.find(remotePath);
    return found == options.davLocks.end() ? std::string() : found->second;
}

/*
 * An entity tag as an If header carries it: quoted, with the 'W/' of a
 * weak tag in front of the quotes.
 *
 * 'etag -get' prints the server's tag with its quotes, and the command
 * splitter reads those quotes as the quoting of the argument, so what the
 * switch hands over is the tag without them. An unquoted tag is not one a
 * server compares, so both spellings are stored the way the header needs
 * it rather than sent as the user happened to type them. '*' is passed
 * through unchanged: it is not an entity tag, and the command that records
 * a precondition refuses it rather than send a condition that would hold
 * on every write and guard nothing.
 */
std::string DavEntityTag(const std::string & value)
{
    std::string text = value;
    std::string weak;
    if (text.compare(0, 2, "W/") == 0)
    {
        weak = "W/";
        text = text.substr(2);
    }
    if (text == "*")
    {
        return text;
    }
    if (text.size() >= 2 && text[0] == '"' && text[text.size() - 1] == '"')
    {
        return weak + text;
    }
    return weak + "\"" + text + "\"";
}

/*
 * The If header a write of this path carries, or an empty string when the
 * session has nothing to state about it.
 *
 * RFC 4918 10.4 reads an If header as either no-tag lists or tagged lists
 * and never as both, every condition inside one list has to hold, and the
 * lists themselves are alternatives. A path that is both locked and has an
 * ETag recorded therefore goes as one list - '(<token> ["etag"])' - which
 * says "I hold this lock and I read this version". It used to go as a
 * no-tag list followed by a tagged one, a header no server is asked to
 * parse, and the lock token went without the angle brackets that make it a
 * Coded-URL, so a server reading the standard grammar found no token in it
 * and answered 423 to the writer that held the lock.
 *
 * The no-tag form is used throughout, so the conditions apply to the
 * resource the request is aimed at: a tagged list spells a URL, and one
 * built from the remote path alone would resolve against the request and
 * could guard a resource nobody was writing.
 *
 * '-nomatch=' is If-None-Match - write only if the version the server has
 * is not this one - which a condition list spells 'Not ["etag"]'. Without
 * the 'Not' it asked for the opposite of what the command's own help
 * promises: a write would have gone through only over the very version the
 * user said they had not seen.
 */
std::string DavIfHeader(const SessionOptions & options,
    const std::string & remotePath)
{
    std::string conditions;
    const std::string lockToken = DavTokenFor(options, remotePath);
    if (!lockToken.empty())
    {
        conditions += "<" + lockToken + ">";
    }
    std::map<std::string, SessionOptions::EtagPrecondition>::const_iterator
        etagFound = options.davEtags.find(remotePath);
    if (etagFound != options.davEtags.end())
    {
        const SessionOptions::EtagPrecondition & precondition =
            etagFound->second;
        /* 'etag' records one action per call, so at most one of the two is
         * set; both are spelled out because a list of conditions is read
         * as the conjunction it is. */
        if (!precondition.ifMatch.empty())
        {
            if (!conditions.empty())
            {
                conditions += " ";
            }
            conditions += "[" + precondition.ifMatch + "]";
        }
        if (!precondition.ifNoneMatch.empty())
        {
            if (!conditions.empty())
            {
                conditions += " ";
            }
            conditions += "Not [" + precondition.ifNoneMatch + "]";
        }
    }
    return conditions.empty() ? std::string() : "(" + conditions + ")";
}

namespace {

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

bool StartsWith(const std::string & text, const char * prefix)
{
    size_t len = strlen(prefix);
    return text.size() >= len && text.compare(0, len, prefix) == 0;
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

/* curl is the transfer engine for every protocol not served by the
 * native libssh SFTP transport or the native SCP engine. */
const std::string & CurlExecutable()
{
    static const std::string executable = [] {
        std::string found = FindExecutableOnPath("curl");
        return found.empty() ? std::string("curl") : found;
    }();
    return executable;
}

int RunCurl(const std::vector<std::string> & args, std::string & outStr,
    std::string & errStr)
{
    int rc = RunCapture(args, outStr, errStr);
    if (rc == -1 && errStr.empty())
    {
        errStr = "Failed to run curl. Install curl (apt install curl) "
            "and make sure it is on PATH.";
    }
    else if (rc == 127 && FindExecutableOnPath("curl").empty())
    {
        errStr = "curl was not found on PATH. Install curl (apt install "
            "curl) to use this protocol.";
    }
    return rc;
}

/*
 * The curl command-line client owns the socket for the non-SFTP protocols.
 * Its progress meter is the portable interface that remains available when
 * LinSCP is built without linking libcurl: it writes rows to stderr, using
 * carriage returns to redraw the same row. Parse those rows in the parent
 * process and forward byte counts through the same callback used by native
 * SFTP. This keeps the Linux conversion dependency-free while still making
 * curl transfers observable to the console and GUI callers.
 */
struct CurlProgressParser
{
    LscpProgressFn callback;
    void * callbackContext;
    bool upload;
    std::string pending;

    CurlProgressParser() : callback(NULL), callbackContext(NULL), upload(false) {}
};

bool ParseCurlSize(const std::string & text, unsigned long long & value)
{
    if (text.empty() || text == "-")
    {
        return false;
    }
    size_t end = 0;
    while (end < text.size() &&
        ((text[end] >= '0' && text[end] <= '9') || text[end] == '.'))
    {
        end++;
    }
    if (end == 0)
    {
        return false;
    }
    const std::string numeric = text.substr(0, end);
    char * numberEnd = NULL;
    const double number = strtod(numeric.c_str(), &numberEnd);
    if (numberEnd == NULL || *numberEnd != '\0' || number < 0)
    {
        return false;
    }
    double multiplier = 1.0;
    if (end < text.size())
    {
        switch (text[end])
        {
        case 'k': case 'K': multiplier = 1024.0; break;
        case 'm': case 'M': multiplier = 1024.0 * 1024.0; break;
        case 'g': case 'G': multiplier = 1024.0 * 1024.0 * 1024.0; break;
        case 't': case 'T': multiplier = 1024.0 * 1024.0 * 1024.0 * 1024.0; break;
        default: return false;
        }
        /* Both 'k' and an explicit 'Ki' are accepted. Curl's human-readable
         * meter uses the binary size convention for these suffixes. */
    }
    const double scaled = number * multiplier;
    if (scaled > static_cast<double>(~0ULL))
    {
        return false;
    }
    value = static_cast<unsigned long long>(scaled + 0.5);
    return true;
}

void ConsumeCurlProgressLine(CurlProgressParser & parser,
    const std::string & line)
{
    if (parser.callback == NULL || line.empty())
    {
        return;
    }
    std::istringstream stream(line);
    std::vector<std::string> fields;
    std::string field;
    while (stream >> field)
    {
        fields.push_back(field);
    }
    /* A curl meter row starts with: total%, total-size, received%,
     * received-size, uploaded%, uploaded-size. Header and final speed
     * lines do not have six fields with numeric sizes, so they are ignored. */
    if (fields.size() < 6)
    {
        return;
    }
    unsigned long long total = 0;
    unsigned long long received = 0;
    unsigned long long uploaded = 0;
    if (!ParseCurlSize(fields[1], total) ||
        !ParseCurlSize(fields[3], received) ||
        !ParseCurlSize(fields[5], uploaded))
    {
        return;
    }
    parser.callback(parser.upload ? uploaded : received, total,
        parser.callbackContext);
}

void CurlProgressOutput(const void * data, size_t len, bool fromStderr,
    void * context)
{
    if (!fromStderr || context == NULL || data == NULL || len == 0)
    {
        return;
    }
    CurlProgressParser & parser = *static_cast<CurlProgressParser *>(context);
    const char * bytes = static_cast<const char *>(data);
    for (size_t i = 0; i < len; i++)
    {
        if (bytes[i] == '\r' || bytes[i] == '\n')
        {
            ConsumeCurlProgressLine(parser, parser.pending);
            parser.pending.clear();
        }
        else
        {
            parser.pending += bytes[i];
        }
    }
}

void FinishCurlProgress(CurlProgressParser & parser)
{
    if (!parser.pending.empty())
    {
        ConsumeCurlProgressLine(parser, parser.pending);
        parser.pending.clear();
    }
}

int RunCurlCaptureWithProgressInternal(const std::vector<std::string> & args,
    std::string & outStr, std::string & errStr, LscpProgressFn callback,
    void * callbackContext, bool upload)
{
    CurlProgressParser parser;
    parser.callback = callback;
    parser.callbackContext = callbackContext;
    parser.upload = upload;
    const int rc = RunCaptureWithOutput(args, outStr, errStr,
        CurlProgressOutput, &parser);
    FinishCurlProgress(parser);
    if (rc == -1 && errStr.empty())
    {
        errStr = "Failed to run curl. Install curl (apt install curl) "
            "and make sure it is on PATH.";
    }
    else if (rc == 127 && FindExecutableOnPath("curl").empty())
    {
        errStr = "curl was not found on PATH. Install curl (apt install "
            "curl) to use this protocol.";
    }
    return rc;
}

/* The progress meter is useful while a transfer runs but should never be
 * presented as the actual error if curl fails. Keep ordinary diagnostics and
 * discard the carriage-returned meter/header rows. */
std::string CurlErrorWithoutProgress(const std::string & text)
{
    std::string result;
    size_t start = 0;
    while (start <= text.size())
    {
        size_t end = text.find_first_of("\r\n", start);
        if (end == std::string::npos)
        {
            end = text.size();
        }
        const std::string line = text.substr(start, end - start);
        std::istringstream stream(line);
        std::vector<std::string> fields;
        std::string field;
        while (stream >> field)
        {
            fields.push_back(field);
        }
        unsigned long long ignored = 0;
        const bool meter = fields.size() >= 6 &&
            ParseCurlSize(fields[1], ignored) &&
            ParseCurlSize(fields[3], ignored) &&
            ParseCurlSize(fields[5], ignored);
        if (!meter && line.find("% Total") == std::string::npos &&
            line.find("--:--:--") == std::string::npos && !line.empty())
        {
            if (!result.empty())
            {
                result += '\n';
            }
            result += line;
        }
        if (end == text.size())
        {
            break;
        }
        start = end + 1;
    }
    return result;
}

std::string BuildUrl(const SessionOptions & options, const std::string & remotePath)
{
    std::string proto = ToLower(options.protocol);
    if (proto == "ftp" && SessionUsesImplicitTls(options))
    {
        /* 'Ftps=1' turns a plain FTP session into an implicit-TLS one. */
        proto = "ftps";
    }
    if (proto == "dav")
    {
        /* Plain WebDAV, with the port 80 default ParseSiteUrl gives it. */
        proto = "http";
    }
    else if (proto == "webdav")
    {
        /* Secure WebDAV, matching the port 443 default. */
        proto = "https";
    }
    else if (proto == "s3")
    {
        proto = "https";
    }

    /* The path is a decoded remote file name, not an already encoded URL.
     * Otherwise a space fails curl's URL parser and '#', '?' or '%' silently
     * address a different resource. Keep only '/' separators unescaped;
     * S3 is dispatched before BuildUrl and signs its own encoded path. */
    const bool ipv6 = options.hostName.find(':') != std::string::npos &&
        (options.hostName.empty() || options.hostName[0] != '[');
    std::string url = proto + "://" +
        (ipv6 ? "[" + options.hostName + "]" : options.hostName);
    /* No SSH protocol is built here: sftp:// goes through libssh and
     * scp:// through the native SCP engine, neither of which is a URL. */
    if (options.portNumber > 0 &&
        !((proto == "ftp" && options.portNumber == 21) ||
          (proto == "ftps" && options.portNumber == 990) ||
          (proto == "http" && options.portNumber == 80) ||
          (proto == "https" && options.portNumber == 443)))
    {
        url += ":" + std::to_string(options.portNumber);
    }

    std::string path = remotePath;
    if (path.empty() || path[0] != '/')
    {
        url += "/";
    }
    url += s3sig::UriEncode(path, true);
    return url;
}


/* The TLS policy of the session as curl arguments. Nothing is added for a
 * plain session, and a policy curl cannot express is refused before the
 * connection (see ValidateSessionSettings), never silently dropped. */
void AddTlsCurlArgs(const SessionOptions & options, std::vector<std::string> & args)
{
    const std::string proto = ToLower(options.protocol);
    const bool ftpFamily = proto == "ftp" || proto == "ftps";
    if (!SessionUsesTls(options))
    {
        return;
    }

    /* An explicit-TLS FTP session is curl's 'ftps' scheme in explicit
     * mode, which is what --ssl-reqd asks for on an ftp:// URL. */
    if (ftpFamily && !SessionUsesImplicitTls(options) &&
        options.tls.ftpsMode != 0)
    {
        args.push_back("--ssl-reqd");
    }

    static const char * const kVersionFlags[4] = {
        "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3"
    };
    static const char * const kMaxValues[4] = { "1.0", "1.1", "1.2", "1.3" };
    if (options.tls.minVersion >= 10 && options.tls.minVersion <= 13)
    {
        args.push_back(kVersionFlags[options.tls.minVersion - 10]);
    }
    if (options.tls.maxVersion >= 10 && options.tls.maxVersion <= 13)
    {
        args.push_back("--tls-max");
        args.push_back(kMaxValues[options.tls.maxVersion - 10]);
    }
    if (!options.tls.clientCertificate.empty())
    {
        args.push_back("--cert");
        args.push_back(options.tls.clientCertificate);
    }
    if (!options.tls.clientKey.empty())
    {
        args.push_back("--key");
        args.push_back(options.tls.clientKey);
    }
    if (!options.tls.caFile.empty())
    {
        args.push_back("--cacert");
        args.push_back(options.tls.caFile);
    }
    if (!options.tls.caDirectory.empty())
    {
        args.push_back("--capath");
        args.push_back(options.tls.caDirectory);
    }
    if (!options.tls.pinnedPublicKey.empty())
    {
        args.push_back("--pinnedpubkey");
        args.push_back(options.tls.pinnedPublicKey);
    }
}

void AddCurlTunnelArgs(const SessionOptions & options, std::vector<std::string> & args)
{
    if (options.tunnelSocksPort <= 0)
    {
        return;
    }
    /* socks5h leaves the destination name to the jump host, which is
     * what keeps TLS SNI, HTTP Host and S3 SigV4 on the original
     * hostname while the TCP connection is 127.0.0.1. --noproxy '*'
     * stops a parent proxy exclusion from sending the destination
     * around the tunnel. */
    args.push_back("--socks5-hostname");
    args.push_back("127.0.0.1:" + std::to_string(options.tunnelSocksPort));
    args.push_back("--noproxy");
    args.push_back("*");
}

void BuildCommonCurlArgs(const SessionOptions & options, std::vector<std::string> & args,
    bool failOnError = true, bool showProgress = false)
{
    args.push_back(CurlExecutable());
    if (!showProgress)
    {
        args.push_back("-s");
    }
    args.push_back("-S");
    if (showProgress)
    {
        /* Do not use -s for a transfer with a progress callback: curl's
         * meter is the byte-count stream parsed above. */
        args.push_back("--progress-meter");
    }
    /*
     * -f (--fail) turns a server-side error into a non-zero exit code
     * instead of a successful transfer of the error document. Without it
     * a missing file on an HTTP(S) server looks like a 335-byte
     * download, and 'stat' reports the error page as the file. WebDAV
     * passes false: it has to read the status code and the error body,
     * which -f would hide.
     */
    if (failOnError)
    {
        args.push_back("-f");
    }

    if (!options.userName.empty())
    {
        std::string cred = options.userName;
        if (!options.password.empty())
        {
            cred += ":" + options.password;
        }
        else if (!StdInIsTerminal())
        {
            /*
             * Without the separator curl asks for the password itself and
             * reads it from stdin. In a '-script=-' run stdin is the
             * command source, so the prompt would eat pending commands (and
             * the prompt text ended up inside error messages). Give curl an
             * explicitly empty password instead; interactive runs still get
             * the prompt.
             */
            cred += ":";
        }
        args.push_back("-u");
        args.push_back(cred);
    }

    if (options.hostKey == "*")
    {
        args.push_back("--insecure");
    }
    /*
     * An SSH host key is not pinned here: no SSH protocol goes through curl
     * any more. sftp:// and scp:// are both served by this client's own SSH
     * engine, which checks the pin itself (Session::HostKeyMatches) and
     * refuses a key that does not match, so there is no curl option whose
     * support would depend on which SSH library the installed curl linked.
     */

    /* 'FtpPasvMode=0' means an active data connection: curl sends PORT
     * instead of PASV/EPSV, reusing the control connection's address. */
    const std::string ftpProto = ToLower(options.protocol);
    if ((ftpProto == "ftp" || ftpProto == "ftps") && !options.ftp.passiveMode)
    {
        args.push_back("-P");
        args.push_back("-");
    }

    AddTlsCurlArgs(options, args);
    AddCurlTunnelArgs(options, args);

    if (!options.privateKeyFile.empty())
    {
        args.push_back("--key");
        args.push_back(ExpandTilde(options.privateKeyFile));
    }

    if (options.timeoutSecs > 0)
    {
        args.push_back("--connect-timeout");
        args.push_back(std::to_string(options.timeoutSecs));
    }

    /*
     * The proxy of the session as curl's own options. Only the methods curl
     * speaks are translated here; a telnet or local-command proxy is refused
     * before a connection is attempted (ProxyUsableByCurl), because going
     * direct when the session asked for a proxy would send traffic where the
     * user did not want it. A destination tunnel already applied the parent
     * proxy to the jump host; curl then speaks only to the loopback SOCKS
     * listener.
     */
    if (options.tunnelSocksPort <= 0 && options.proxy.Active())
    {
        const ProxySettings & proxy = options.proxy;
        const char * scheme = NULL;
        switch (proxy.method)
        {
        case ProxyMethod::Socks4: scheme = "socks4"; break;
        case ProxyMethod::Socks5:
            /* 'socks5h' leaves the name to the proxy, which is what
             * ProxyDNS=on (and, except for SOCKS4, automatic) means. */
            scheme = proxy.ResolvesRemotely() ? "socks5h" : "socks5";
            break;
        case ProxyMethod::Http:   scheme = "http";   break;
        default: break;
        }
        if (scheme != NULL)
        {
            args.push_back("--proxy");
            args.push_back(std::string(scheme) + "://" + proxy.host + ":" +
                std::to_string(proxy.EffectivePort()));
        }
        if (!proxy.userName.empty())
        {
            args.push_back("--proxy-user");
            args.push_back(proxy.userName + ":" + proxy.password);
        }
        /* the session format separates ProxyExcludeList entries by whitespace or comma,
         * while curl expects commas. Add curl's loopback exclusions for
         * the default ProxyLocalhost=0 policy. CIDR matching handles all
         * of IPv4's loopback block, not just 127.0.0.1; localhost and ::1
         * cover the usual name and IPv6 loopback forms. */
        std::string list;
        for (size_t i = 0; i < proxy.excludeList.size(); i++)
        {
            const char c = proxy.excludeList[i];
            if (c == ',' || c == ';' || c == '\n' || c == '\r' ||
                c == ' ' || c == '\t')
            {
                if (!list.empty() && list[list.size() - 1] != ',')
                {
                    list += ",";
                }
            }
            else
            {
                list += c;
            }
        }
        if (!proxy.evenLocalhost)
        {
            if (!list.empty() && list[list.size() - 1] != ',')
            {
                list += ",";
            }
            list += "localhost,127.0.0.0/8,::1/128";
        }
        if (!list.empty())
        {
            args.push_back("--noproxy");
            args.push_back(list);
        }
    }
}

/*
 * Runs one directory listing and parses it. Both the long 'ls -l' format
 * (what FTP servers and curl's own SFTP engine produce) and a names-only
 * listing are understood; the latter leaves 'typeKnown' false.
 */
/*
 * The curl exit codes that say the endpoint itself is unusable: it could not
 * be reached, the transport failed, or it refused us at the protocol level.
 * Anything else (a directory that is not listable, a file that is not there)
 * is the server answering, which 'open' must not second-guess - the command
 * that needs that path reports it.
 */
bool IsEndpointUnreachable(int code)
{
    switch (code)
    {
    case -1:              /* curl could not be run at all */
    case 1:               /* this curl was not built with the protocol */
    case 3:               /* the URL was malformed */
    case 5:               /* could not resolve the proxy */
    case 6:               /* could not resolve the host */
    case 7:               /* could not connect */
    case 28:              /* timed out */
    case 35:              /* TLS handshake failed */
    case 51: case 53: case 54: case 55: case 56: case 58: case 59:
    case 60: case 64: case 66: case 67: case 77: case 80: case 82:
    case 83: case 84: case 90: case 91: case 92: case 94: case 95:
    case 96: case 97:
        return true;
    default:
        return false;
    }
}

bool FetchListing(const SessionOptions & options, const std::string & remotePath,
    std::vector<ListingEntry> & entries, std::string & error, int * codeOut = NULL)
{
    entries.clear();

    std::string path = remotePath;
    if (path.empty() || path.back() != '/')
    {
        path += "/";
    }

    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args);
    args.push_back(BuildUrl(options, path));

    std::string outStr;
    std::string errStr;
    const int rc = RunCurl(args, outStr, errStr);
    if (codeOut != NULL)
    {
        *codeOut = rc;
    }
    if (rc != 0)
    {
        error = errStr.empty() ? "Curl error " + std::to_string(rc) : errStr;
        return false;
    }

    std::istringstream stream(outStr);
    std::string line;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        if (line.empty() || line == "." || line == "..")
        {
            continue;
        }

        ListingEntry entry;
        entry.longname = line;

        if (!ParseAnyListingLine(line, entry))
        {
            entry.name = line;
            if (!entry.name.empty() && entry.name.back() == '/')
            {
                entry.name.pop_back();
                entry.typeKnown = true;
                entry.isDir = true;
                entry.permissions = 0040755;
            }
        }
        if (entry.name.empty() || entry.name == "." || entry.name == "..")
        {
            continue;
        }
        entries.push_back(entry);
    }
    return true;
}

std::string OctalPermissions(int permissions)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%o", static_cast<unsigned int>(permissions));
    return std::string(buffer);
}

/* ---- WebDAV (dav / webdav) --------------------------------------------
 *
 * The listing, stat and directory operations of a DAV session go through
 * PROPFIND and the status-checked MKCOL/DELETE/MOVE verbs rather than the
 * GET-directory-text parser above: a WebDAV server is not required to
 * produce a browsable page for a collection, and its properties (type,
 * length, modification date) are the real metadata. Transfers stay on the
 * generic GET/PUT paths - those are what HTTP already means.
 */

const char * const kDavPropfindBody =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<propfind xmlns=\"DAV:\"><prop>"
    "<resourcetype/><getcontentlength/><getlastmodified/><getetag/>"
    "</prop></propfind>";

int HexDigitValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string DavPercentDecode(const std::string & input)
{
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); i++)
    {
        if (input[i] == '%' && i + 2 < input.size())
        {
            const int high = HexDigitValue(input[i + 1]);
            const int low = HexDigitValue(input[i + 2]);
            if (high >= 0 && low >= 0)
            {
                out += static_cast<char>((high << 4) | low);
                i += 2;
                continue;
            }
        }
        out += input[i];
    }
    return out;
}

/* The remote-path form we compare in: leading slash and no trailing slash
 * (except the root itself). A decoded file name may itself contain '?' or
 * '#'; they are NOT URI delimiters here. Strip those only from an href,
 * before percent-decoding it. */
std::string DavNormalizePath(const std::string & raw)
{
    std::string path = raw;
    if (path.empty() || path[0] != '/')
    {
        path = "/" + path;
    }
    while (path.size() > 1 && path[path.size() - 1] == '/')
    {
        path.erase(path.size() - 1);
    }
    return path;
}

/* An href is either an absolute-path reference or a full URI; both land
 * on our path space after this. Percent-escapes are decoded (servers
 * escape every segment; a name's own '/' cannot appear decoded). */
std::string DavHrefToPath(const std::string & rawHref)
{
    std::string href = rawHref;
    const size_t scheme = href.find("://");
    if (scheme != std::string::npos)
    {
        const size_t pathStart = href.find('/', scheme + 3);
        href = (pathStart == std::string::npos) ? std::string("/") :
            href.substr(pathStart);
    }
    const size_t suffix = href.find_first_of("?#");
    if (suffix != std::string::npos)
    {
        href.resize(suffix);
    }
    return DavNormalizePath(DavPercentDecode(href));
}

/* Element search by local name: the DAV prefix (d:, D:, or none) is the
 * server's choice, so '<getcontentlength>' and '<d:getcontentlength>'
 * are the same element to us. Returns the offset of the '<'. */
bool DavScanElement(const std::string & xml, const std::string & local,
    size_t from, size_t & tagStart, std::string & fullName)
{
    size_t pos = from;
    while ((pos = xml.find('<', pos)) != std::string::npos)
    {
        const size_t nameStart = pos + 1;
        if (nameStart >= xml.size())
        {
            return false;
        }
        const char c = xml[nameStart];
        if (c == '?' || c == '!' || c == '/')
        {
            pos = nameStart;
            continue;
        }
        size_t nameEnd = nameStart;
        while (nameEnd < xml.size() &&
            (isalnum(static_cast<unsigned char>(xml[nameEnd])) ||
             xml[nameEnd] == ':' || xml[nameEnd] == '-' ||
             xml[nameEnd] == '_'))
        {
            nameEnd++;
        }
        const std::string full = xml.substr(nameStart, nameEnd - nameStart);
        const size_t colon = full.rfind(':');
        const std::string localName = colon == std::string::npos ?
            full : full.substr(colon + 1);
        if (localName == local)
        {
            tagStart = pos;
            fullName = full;
            return true;
        }
        pos = nameEnd > pos ? nameEnd : pos + 1;
    }
    return false;
}

/* Content between the open tag at tagStart and its close (empty for a
 * self-closing tag). 'bodyEnd' is where the content stops - the closing
 * tag's '<', which is what a text extraction has to stop at - and
 * 'after' is the offset past the whole element, which is what block
 * extraction walks on. */
bool DavElementBody(const std::string & xml, size_t tagStart,
    const std::string & fullName, size_t & bodyStart, size_t & bodyEnd,
    size_t & after)
{
    const size_t gt = xml.find('>', tagStart);
    if (gt == std::string::npos)
    {
        return false;
    }
    if (gt > tagStart && xml[gt - 1] == '/')
    {
        bodyStart = bodyEnd = after = gt + 1;
        return true;
    }
    const std::string closing = "</" + fullName + ">";
    const size_t end = xml.find(closing, gt + 1);
    if (end == std::string::npos)
    {
        return false;
    }
    bodyStart = gt + 1;
    bodyEnd = end;
    after = end + closing.size();
    return true;
}

/*
 * The text of an element with XML's character references resolved.
 *
 * A server may escape what it puts inside an element, and a value that is
 * itself quoted - an entity tag - arrives as '&quot;abc&quot;' from one
 * that does. Handing that back as the tag left a precondition no server
 * could match, and a path or a property value with an ampersand in it came
 * back spelled differently from the way it was stored, so every value read
 * out of a reply is resolved on the way out. Only the five references XML
 * defines are: a numeric one is left as it came rather than half-decoded.
 */
std::string DavXmlUnescape(const std::string & text)
{
    static const struct
    {
        const char * name;
        char value;
    } kEntities[] = {
        { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' },
        { "&quot;", '"' }, { "&apos;", '\'' },
    };
    std::string out;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] != '&')
        {
            out += text[i];
            continue;
        }
        bool resolved = false;
        for (size_t e = 0; e < sizeof(kEntities) / sizeof(kEntities[0]); e++)
        {
            const size_t length = strlen(kEntities[e].name);
            if (text.compare(i, length, kEntities[e].name) == 0)
            {
                out += kEntities[e].value;
                i += length - 1;
                resolved = true;
                break;
            }
        }
        if (!resolved)
        {
            out += text[i];
        }
    }
    return out;
}

bool DavFindText(const std::string & xml, const std::string & local,
    size_t from, std::string & value)
{
    size_t tagStart;
    std::string full;
    if (!DavScanElement(xml, local, from, tagStart, full))
    {
        return false;
    }
    size_t bodyStart, bodyEnd, after;
    if (!DavElementBody(xml, tagStart, full, bodyStart, bodyEnd, after))
    {
        return false;
    }
    value = DavXmlUnescape(xml.substr(bodyStart, bodyEnd - bodyStart));
    return true;
}

struct DavResponse
{
    std::string path;
    bool isDir;
    bool hasSize;
    unsigned long long size;
    bool hasTime;
    unsigned long mtime;
    std::string etag;
};

bool DavParseMultiStatus(const std::string & xml,
    std::vector<DavResponse> & out, std::string & error)
{
    size_t pos = 0;
    bool any = false;
    size_t tagStart;
    std::string full;
    while (DavScanElement(xml, "response", pos, tagStart, full))
    {
        size_t bodyStart, bodyEnd, after;
        if (!DavElementBody(xml, tagStart, full, bodyStart, bodyEnd, after))
        {
            error = "Malformed WebDAV multi-status (unclosed <" + full + ">).";
            return false;
        }
        (void)bodyEnd;
        pos = after;
        any = true;
        const std::string block = xml.substr(bodyStart, after - bodyStart);
        std::string href;
        if (!DavFindText(block, "href", 0, href) || href.empty())
        {
            continue;
        }
        DavResponse entry;
        entry.path = DavHrefToPath(href);
        entry.isDir = false;
        entry.hasSize = false;
        entry.size = 0;
        entry.hasTime = false;
        entry.mtime = 0;
        /* Only properties whose propstat says 200 exist; a 404 propstat
         * is the server answering that it does not carry them. */
        size_t ppos = 0;
        size_t pTag;
        std::string pFull;
        while (DavScanElement(block, "propstat", ppos, pTag, pFull))
        {
            size_t pBody, pBodyEnd, pAfter;
            if (!DavElementBody(block, pTag, pFull, pBody, pBodyEnd, pAfter))
            {
                break;
            }
            (void)pBodyEnd;
            ppos = pAfter;
            const std::string propstat = block.substr(pBody, pAfter - pBody);
            std::string status;
            if (!DavFindText(propstat, "status", 0, status) ||
                status.find(" 200") == std::string::npos)
            {
                continue;
            }
            size_t cTag;
            std::string cFull;
            if (DavScanElement(propstat, "collection", 0, cTag, cFull))
            {
                entry.isDir = true;
            }
            std::string text;
            if (DavFindText(propstat, "getcontentlength", 0, text) &&
                !text.empty())
            {
                entry.hasSize = true;
                entry.size = strtoull(text.c_str(), NULL, 10);
            }
            if (DavFindText(propstat, "getlastmodified", 0, text) &&
                !text.empty())
            {
                const unsigned long stamp = ParseHttpDate(text);
                if (stamp != 0)
                {
                    entry.hasTime = true;
                    entry.mtime = stamp;
                }
            }
            text.clear();
            if (DavFindText(propstat, "getetag", 0, text) && !text.empty())
            {
                entry.etag = text;
            }
        }
        out.push_back(entry);
    }
    if (!any && xml.find("multistatus") == std::string::npos)
    {
        error = "The server did not answer with a WebDAV multi-status.";
        return false;
    }
    return true;
}

struct DavResult
{
    int curlCode;
    int httpCode;
    std::string out;
    std::string err;
};

/*
 * One status-checked WebDAV verb. The status line comes from -w (curl's
 * exit code cannot distinguish 404 from 403 without -f, and -f would
 * hide the body we quote back), --anyauth lets a digest-only server
 * challenge us instead of the pre-emptive basic credentials failing
 * outright. Returns false only when the transport itself failed;
 * otherwise httpCode carries the server's answer.
 */
bool DavInvoke(const SessionOptions & options, const std::string & method,
    const std::string & remotePath,
    const std::vector<std::pair<std::string, std::string> > & headers,
    const std::string & body, DavResult & result, std::string & error,
    const std::string & ifToken = std::string())
{
    result.curlCode = -1;
    result.httpCode = 0;
    result.out.clear();
    result.err.clear();

    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args, false);
    args.push_back("--anyauth");
    args.push_back("-X");
    args.push_back(method);
    if (!ifToken.empty())
    {
        args.push_back("-H");
        args.push_back("If: (" + ifToken + ")");
    }
    for (size_t i = 0; i < headers.size(); i++)
    {
        args.push_back("-H");
        args.push_back(headers[i].first + ": " + headers[i].second);
    }
    if (!body.empty())
    {
        args.push_back("--data-binary");
        args.push_back(body);
    }
    args.push_back("-w");
    args.push_back("\n%{http_code}");
    args.push_back(BuildUrl(options, remotePath));

    std::string outStr;
    std::string errStr;
    const int rc = RunCurl(args, outStr, errStr);
    result.curlCode = rc;
    result.err = errStr;

    /* The body, then the three-digit status the -w appended after a
     * newline (the body itself may contain newlines, so take the last). */
    const size_t newline = outStr.rfind('\n');
    if (newline != std::string::npos && outStr.size() >= newline + 4 &&
        isdigit(static_cast<unsigned char>(outStr[newline + 1])) &&
        isdigit(static_cast<unsigned char>(outStr[newline + 2])) &&
        isdigit(static_cast<unsigned char>(outStr[newline + 3])) &&
        outStr.size() == newline + 4)
    {
        result.httpCode = atoi(outStr.substr(newline + 1, 3).c_str());
        result.out = outStr.substr(0, newline);
    }
    else
    {
        result.out = outStr;
    }

    if (result.httpCode == 0)
    {
        error = errStr.empty() ?
            ("Curl error " + std::to_string(rc) + ".") : errStr;
        return false;
    }
    return true;
}

/* The plain-language failure for a non-2xx status, quoting the server
 * when it said something we can show. */
std::string DavHttpFailure(const DavResult & result, const char * what)
{
    std::string message = std::string(what) + " failed: WebDAV error " +
        std::to_string(result.httpCode) + ".";
    if (result.httpCode == 401)
    {
        return "401 Unauthorized: the server rejected the user name or "
            "password.";
    }
    const std::string & body = result.out;
    if (!body.empty() && body[0] != '<')
    {
        /* Plain-text error bodies (what servers like to send for 4xx) */
        size_t end = body.find_first_of("\r\n");
        if (end == std::string::npos)
        {
            end = body.size();
        }
        if (end > 200)
        {
            end = 200;
        }
        message += " " + body.substr(0, end);
    }
    return message;
}

bool DavPropfindOnce(const SessionOptions & options, const std::string & path,
    const char * depth, DavResult & result, std::string & error)
{
    std::vector<std::pair<std::string, std::string> > headers;
    headers.push_back(std::make_pair(std::string("Depth"), std::string(depth)));
    headers.push_back(std::make_pair(std::string("Content-Type"),
        std::string("application/xml")));
    if (!DavInvoke(options, "PROPFIND", path, headers, kDavPropfindBody,
        result, error))
    {
        return false;
    }
    if (result.httpCode == 207 || result.httpCode == 200)
    {
        return true;
    }
    if (result.httpCode == 404)
    {
        error = "No such file or directory.";
    }
    else if (result.httpCode == 405)
    {
        error = "PROPFIND is not allowed by the server.";
    }
    else
    {
        error = DavHttpFailure(result, "List");
    }
    return true; /* the server answered; 'error' says what it said */
}

/*
 * WebDAV locks and dead properties: what upstream's WebDAV backend does
 * not have at all, and therefore a LinSCP extension. A lock is what keeps
 * two writers from racing over the same path, the If header is what makes
 * the server enforce it, and a dead property is what a WebDAV server lets
 * a client store next to a file's content. Everything here reports the
 * server's answer: a 405 says the server has no LOCK, and the command
 * prints that rather than reporting a write that was never protected.
 */

const char * const kDavPropertyNamespace = "urn:linscp:properties";
const char * const kDavPropertyPrefix = "lscp";

std::string DavTrimmed(const std::string & text)
{
    size_t begin = 0;
    while (begin < text.size() && isspace(static_cast<unsigned char>(text[begin])))
    {
        begin++;
    }
    size_t end = text.size();
    while (end > begin && isspace(static_cast<unsigned char>(text[end - 1])))
    {
        end--;
    }
    return text.substr(begin, end - begin);
}

std::string DavXmlEscape(const std::string & text)
{
    std::string out;
    for (size_t i = 0; i < text.size(); i++)
    {
        switch (text[i])
        {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        default: out += text[i]; break;
        }
    }
    return out;
}


/* The first failing status inside a 207 reply, for PROPPATCH answers: a
 * multi-status can carry one propstat per property, and a property the
 * server refused has to be reported rather than counted as stored. */
std::string DavMultiStatusFailure(const std::string & xml)
{
    size_t at = 0;
    while ((at = xml.find("status", at)) != std::string::npos)
    {
        const size_t gt = xml.find('>', at);
        if (gt == std::string::npos)
        {
            break;
        }
        const size_t lt = xml.find('<', gt + 1);
        const std::string text = lt == std::string::npos ?
            std::string() : DavTrimmed(xml.substr(gt + 1, lt - gt - 1));
        const size_t space = text.find(' ');
        const std::string code = space == std::string::npos ?
            std::string() : text.substr(0, space);
        if (code.size() == 3 && isdigit(static_cast<unsigned char>(code[0])) &&
            code[0] >= '4')
        {
            return text;
        }
        at = lt == std::string::npos ? xml.size() : lt;
    }
    return std::string();
}

/* PROPFIND into listing entries. 'self' (the requested path) is not an
 * entry of its own. */
bool DavFetchListing(const SessionOptions & options,
    const std::string & remotePath, std::vector<ListingEntry> & entries,
    std::string & error, int * codeOut = NULL)
{
    const std::string dir = remotePath.empty() ? std::string("/") : remotePath;
    DavResult result;
    if (!DavPropfindOnce(options, dir, "1", result, error))
    {
        if (codeOut != NULL)
        {
            *codeOut = result.curlCode;
        }
        return false;
    }
    if (codeOut != NULL)
    {
        *codeOut = result.httpCode;
    }
    if (!error.empty())
    {
        return false;
    }

    std::vector<DavResponse> responses;
    if (!DavParseMultiStatus(result.out, responses, error))
    {
        return false;
    }
    const std::string self = DavNormalizePath(dir);
    for (size_t i = 0; i < responses.size(); i++)
    {
        if (responses[i].path == self)
        {
            continue;
        }
        const size_t slash = responses[i].path.rfind('/');
        std::string name = slash == std::string::npos ?
            responses[i].path : responses[i].path.substr(slash + 1);
        if (name.empty() || name == "." || name == "..")
        {
            continue;
        }
        ListingEntry entry;
        entry.name = name;
        entry.longname.clear(); /* the script formats from the attributes */
        entry.typeKnown = true;
        entry.isDir = responses[i].isDir;
        entry.permissions = responses[i].isDir ? 0040755UL : 0100644UL;
        entry.size = responses[i].hasSize ? responses[i].size : 0;
        entry.timeKnown = responses[i].hasTime;
        entry.mtime = responses[i].mtime;
        entries.push_back(entry);
    }
    return true;
}





/* DELETE with the statuses that mean something. 'emptyDirectory' shapes
 * the 409 message: for rmdir, a conflict is the server saying the
 * directory still has children. */
int DavDelete(const SessionOptions & options, const std::string & remotePath,
    bool emptyDirectory, std::string & error)
{
    const std::string davIfHeader = DavIfHeader(options, remotePath);
    DavResult deleted;
    if (!DavInvoke(options, "DELETE", remotePath,
        std::vector<std::pair<std::string, std::string> >(),
        std::string(), deleted, error, davIfHeader))
    {
        return -1;
    }
    if (deleted.httpCode == 200 || deleted.httpCode == 204 ||
        deleted.httpCode == 202)
    {
        return 0;
    }
    if (deleted.httpCode == 404)
    {
        error = "No such file or directory.";
        return -1;
    }
    if (deleted.httpCode == 401)
    {
        error = DavHttpFailure(deleted, "Delete");
        return -1;
    }
    if (deleted.httpCode == 409)
    {
        error = emptyDirectory ?
            "The directory is not empty." :
            "The resource is not empty or is in use.";
        return -1;
    }
    error = DavHttpFailure(deleted, "Delete");
    return -1;
}

} // namespace

int RunCurlCaptureWithProgress(const std::vector<std::string> & args,
    std::string & out, std::string & error, LscpProgressFn progress,
    void * progressCtx, bool upload)
{
    return RunCurlCaptureWithProgressInternal(args, out, error, progress,
        progressCtx, upload);
}

bool IsCurlEndpointUnreachable(int code)
{
    return IsEndpointUnreachable(code);
}

bool ProtocolClient::IsDavProtocol(const std::string & proto)
{
    /* Lowercased here so a caller can hand over the protocol as the user
     * spelled it; the backend's own call sites already lowercase. */
    const std::string p = ToLower(proto);
    return p == "dav" || p == "webdav";
}

bool ProtocolClient::IsMultiProtocol(const std::string & proto)
{
    /* The protocols this curl backend serves. Neither SSH protocol is one
     * of them: sftp:// goes through the native libssh SFTP engine and
     * scp:// through the native SCP engine (ScpClient.cpp). */
    std::string p = ToLower(proto);
    return p == "ftp" || p == "ftps" || p == "http" || p == "https" ||
        p == "dav" || p == "webdav" || p == "s3";
}

void ProtocolClient::FreeNames(LscpNames * names)
{
    if (names == NULL || names->names == NULL)
    {
        return;
    }
    for (int i = 0; i < names->count; i++)
    {
        free(names->names[i].filename);
        free(names->names[i].longname);
    }
    free(names->names);
    names->names = NULL;
    names->count = 0;
}

/* One place that turns listing entries into the names array the rest of
 * the client (and the SFTP path) hands around. */
bool FillNames(const std::vector<ListingEntry> & entries, LscpNames * names,
    std::string & error)
{
    names->count = 0;
    names->names = NULL;
    names->count = static_cast<int>(entries.size());
    if (names->count == 0)
    {
        return true;
    }
    names->names = static_cast<LscpName *>(calloc(names->count, sizeof(LscpName)));
    if (names->names == NULL)
    {
        error = "Out of memory allocating directory entries.";
        names->count = 0;
        return false;
    }
    for (int i = 0; i < names->count; i++)
    {
        names->names[i].filename = DupString(entries[i].name);
        names->names[i].longname = DupString(entries[i].longname);
        names->names[i].attrs.flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
        names->names[i].attrs.permissions = entries[i].permissions;
        names->names[i].attrs.size = entries[i].size;
        if (entries[i].timeKnown)
        {
            names->names[i].attrs.flags |= LSCP_ATTR_ACMODTIME;
            names->names[i].attrs.atime = entries[i].mtime;
            names->names[i].attrs.mtime = entries[i].mtime;
        }
    }
    return true;
}

bool ProtocolClient::List(const SessionOptions & options, const std::string & remotePath,
    LscpNames * names, std::string & error)
{
    if (ScpClient::Handles(options))
    {
        /* SCP is a shell: the listing is an 'ls -l -a' whose lines the
         * parser shared with the curl and FTP backends reads. */
        if (names == NULL)
        {
            error = "Null output pointer.";
            return false;
        }
        names->count = 0;
        names->names = NULL;
        std::vector<ListingEntry> nativeEntries;
        if (!ScpClient::List(options, remotePath, nativeEntries, error))
        {
            return false;
        }
        return FillNames(nativeEntries, names, error);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::List(options, remotePath, names, error);
    }
    if (FtpClient::Handles(options))
    {
        /* Plain FTP goes to the native engine, which speaks MLSD/MLST and
         * honours FtpPasvMode/FtpUseMlsd; the curl path below keeps the
         * TLS FTP sessions and the servers whose listing needs it. */
        if (names == NULL)
        {
            error = "Null output pointer.";
            return false;
        }
        names->count = 0;
        names->names = NULL;
        std::vector<ListingEntry> nativeEntries;
        if (!FtpClient::List(options, remotePath, nativeEntries, error))
        {
            return false;
        }
        return FillNames(nativeEntries, names, error);
    }
    if (names == NULL)
    {
        error = "Null output pointer.";
        return false;
    }
    names->count = 0;
    names->names = NULL;

    std::vector<ListingEntry> entries;
    if (IsDavProtocol(ToLower(options.protocol)))
    {
        if (!DavFetchListing(options, remotePath, entries, error))
        {
            return false;
        }
    }
    else if (!FetchListing(options, remotePath, entries, error))
    {
        return false;
    }

    return FillNames(entries, names, error);
}

bool ProtocolClient::CheckEndpoint(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    /* The curl protocols have no connection of their own, so this is where
     * a policy this build cannot carry out - a TLS certificate fingerprint
     * it cannot check, a TLS setting on a plain session - is refused
     * before anything is sent. */
    if (!ValidateSessionSettings(options, error))
    {
        return false;
    }
    if (ScpClient::Handles(options))
    {
        /* The native engine really connects, so this is a connection test
         * in the same sense as the SFTP one: a host key that does not
         * match, a refused login or a dead port fails the open here. */
        return ScpClient::CheckEndpoint(options, remotePath, error);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::CheckEndpoint(options, remotePath, error);
    }
    std::string path = remotePath.empty() ? std::string("/") : remotePath;
    if (IsDavProtocol(ToLower(options.protocol)))
    {
        /*
         * PROPFIND is what a DAV session will live on; GET of the same
         * path may well be refused by a server that only serves DAV.
         * 401 after --anyauth means the credentials themselves were
         * rejected, 405 means this is not a WebDAV server at all - both
         * stop 'open', where a 403 or 404 on the initial directory is
         * the command's problem to report later, not the connection's.
         */
        DavResult probe;
        std::string probeError;
        if (!DavPropfindOnce(options, path, "0", probe, probeError))
        {
            error = probeError;
            if (IsEndpointUnreachable(probe.curlCode))
            {
                if (probe.curlCode == 1)
                {
                    error += " This curl does not support the '" +
                        options.protocol + "' protocol; install a curl built "
                        "with the support it needs.";
                }
                if (error.empty())
                {
                    error = "Curl error " + std::to_string(probe.curlCode) + ".";
                }
                return false;
            }
            if (error.empty())
            {
                error = "Curl error " + std::to_string(probe.curlCode) + ".";
            }
            return false;
        }
        if (probe.httpCode == 401)
        {
            error = DavHttpFailure(probe, "Connect");
            return false;
        }
        if (probe.httpCode == 405)
        {
            error = "The server does not support WebDAV: PROPFIND is not "
                "allowed.";
            return false;
        }
        if (probe.httpCode >= 500)
        {
            error = DavHttpFailure(probe, "Connect");
            return false;
        }
        /* 207/200 is the session; anything else 4xx is reachable. */
        error.clear();
        return true;
    }
    if (FtpClient::Handles(options))
    {
        /* The native FTP engine opens its own control connection, so this
         * is a real connection test: a refused login or an unreachable
         * host fails the open here, while a directory the server will not
         * list is left to the command that asks for it. */
        std::vector<ListingEntry> nativeEntries;
        int ftpCode = 0;
        if (FtpClient::List(options, path, nativeEntries, error, &ftpCode))
        {
            return true;
        }
        if (ftpCode != kFtpTransportFailure)
        {
            error.clear();
            return true;
        }
        if (error.empty())
        {
            error = "The FTP server could not be reached.";
        }
        return false;
    }

    std::vector<ListingEntry> entries;
    int code = 0;
    if (FetchListing(options, path, entries, error, &code))
    {
        return true;
    }
    if (!IsEndpointUnreachable(code))
    {
        /* We reached the server: it just did not like that directory, which
         * is the command's problem to report, not the connection's. */
        error.clear();
        return true;
    }
    if (code == 1)
    {
        /*
         * Worth saying in our own words: a curl built without the protocol
         * fails every command of such a session, and a user cannot tell that
         * apart from a broken host. (SFTP is not at risk here: it goes
         * through the native libssh transport.)
         */
        error += " This curl does not support the '" + options.protocol +
            "' protocol; install a curl built with the support it needs.";
    }
    if (error.empty())
    {
        error = "Curl error " + std::to_string(code) + ".";
    }
    return false;
}

int ProtocolClient::Stat(const SessionOptions & options, const std::string & remotePath,
    LscpAttrs * attrs, std::string & error)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::Stat(options, remotePath, attrs, error);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::Stat(options, remotePath, attrs, error);
    }
    if (FtpClient::Handles(options))
    {
        return FtpClient::Stat(options, remotePath, attrs, error);
    }
    if (attrs != NULL)
    {
        memset(attrs, 0, sizeof(*attrs));
    }

    std::string proto = ToLower(options.protocol);
    if (IsDavProtocol(proto))
    {
        DavResult probe;
        if (!DavPropfindOnce(options, remotePath, "0", probe, error))
        {
            return LSCP_SFTP_STAT_ERROR;
        }
        if (probe.httpCode == 404)
        {
            return LSCP_SFTP_STAT_MISSING;
        }
        if (probe.httpCode == 401 || probe.httpCode >= 400)
        {
            error = DavHttpFailure(probe, "Stat");
            return LSCP_SFTP_STAT_ERROR;
        }
        std::vector<DavResponse> responses;
        if (!DavParseMultiStatus(probe.out, responses, error))
        {
            return LSCP_SFTP_STAT_ERROR;
        }
        const std::string wanted = DavNormalizePath(remotePath);
        const DavResponse * found = NULL;
        for (size_t i = 0; i < responses.size(); i++)
        {
            if (responses[i].path == wanted)
            {
                found = &responses[i];
                break;
            }
        }
        if (found == NULL && responses.size() == 1)
        {
            /* Some servers emit their own href with a prefix we did not
             * ask with; one answer to Depth: 0 can only be about the
             * path we asked about. */
            found = &responses[0];
        }
        if (found == NULL)
        {
            return LSCP_SFTP_STAT_MISSING;
        }
        if (attrs != NULL)
        {
            attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
            attrs->permissions = found->isDir ? 0040755UL : 0100644UL;
            attrs->size = found->hasSize ? found->size : 0;
            if (found->hasTime)
            {
                attrs->flags |= LSCP_ATTR_ACMODTIME;
                attrs->atime = found->mtime;
                attrs->mtime = found->mtime;
            }
        }
        return LSCP_SFTP_STAT_EXISTS;
    }
    if (proto == "sftp" || proto == "ftp" || proto == "ftps")
    {
        /*
         * curl cannot HEAD an SFTP path at all, and for FTP a HEAD asks
         * for the SIZE of a file, which a directory does not have. Look
         * the name up in its parent directory instead.
         */
        std::string fileName = RemoteFileName(remotePath);
        if (fileName.empty())
        {
            if (attrs != NULL)
            {
                attrs->flags = LSCP_ATTR_PERMISSIONS;
                attrs->permissions = 0040755;
            }
            return LSCP_SFTP_STAT_EXISTS;
        }
        std::string parent = RemoteDirName(remotePath);
        if (parent.empty())
        {
            parent = "/";
        }
        std::vector<ListingEntry> entries;
        if (!FetchListing(options, parent, entries, error))
        {
            return LSCP_SFTP_STAT_ERROR;
        }
        for (size_t i = 0; i < entries.size(); i++)
        {
            if (entries[i].name != fileName)
            {
                continue;
            }
            if (attrs != NULL)
            {
                attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
                attrs->permissions = entries[i].permissions;
                attrs->size = entries[i].size;
                if (entries[i].timeKnown)
                {
                    attrs->flags |= LSCP_ATTR_ACMODTIME;
                    attrs->atime = entries[i].mtime;
                    attrs->mtime = entries[i].mtime;
                }
            }
            return LSCP_SFTP_STAT_EXISTS;
        }
        error = "No such file or directory.";
        return LSCP_SFTP_STAT_MISSING;
    }

    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args);
    args.push_back("-I"); // HEAD request
    args.push_back(BuildUrl(options, remotePath));

    std::string outStr;
    std::string errStr;
    const int rc = RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        error = errStr;
        return LSCP_SFTP_STAT_MISSING;
    }

    if (attrs != NULL)
    {
        attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
        attrs->permissions = 0100644;
        attrs->size = 0;
        std::istringstream stream(outStr);
        std::string line;
        while (std::getline(stream, line))
        {
            const std::string lower = ToLower(line);
            const size_t pos = line.find(':');
            if (pos == std::string::npos)
            {
                continue;
            }
            if (StartsWith(lower, "content-length:"))
            {
                try {
                    attrs->size = std::stoull(line.substr(pos + 1));
                } catch (...) {}
            }
            else if (StartsWith(lower, "last-modified:"))
            {
                const unsigned long stamp = ParseHttpDate(line.substr(pos + 1));
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

int ProtocolClient::Get(const SessionOptions & options, const std::string & remotePath,
    const std::string & localPath, unsigned long long resumeOffset,
    bool preserveTime, unsigned long long * size, LscpProgressFn progress,
    void * progressCtx, std::string & error, unsigned speedKBytesPerSecond)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::Get(options, remotePath, localPath, resumeOffset,
            preserveTime, size, progress, progressCtx, error,
            speedKBytesPerSecond);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::Get(options, remotePath, localPath, resumeOffset,
            preserveTime, size, progress, progressCtx, error,
            speedKBytesPerSecond);
    }
    if (size != NULL)
    {
        *size = 0;
    }

    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args, true, progress != NULL);

    if (resumeOffset > 0)
    {
        args.push_back("-C");
        args.push_back(std::to_string(resumeOffset));
    }

    if (preserveTime)
    {
        /* Give the downloaded file the server's timestamps where the
         * protocol carries them (FTP, SFTP, SCP, HTTP Last-Modified). */
        args.push_back("-R");
    }

    if (speedKBytesPerSecond > 0)
    {
        args.push_back("--limit-rate");
        args.push_back(std::to_string(speedKBytesPerSecond) + "k");
    }

    args.push_back("-o");
    args.push_back(localPath);
    args.push_back(BuildUrl(options, remotePath));

    std::string outStr;
    std::string errStr;
    int rc = progress != NULL ?
        RunCurlCaptureWithProgress(args, outStr, errStr, progress, progressCtx, false) :
        RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        errStr = CurlErrorWithoutProgress(errStr);
        error = errStr.empty() ? "Download failed with exit code " + std::to_string(rc) : errStr;
        return -1;
    }

    LocalFileInfo info = StatLocal(localPath);
    if (progress != NULL && info.exists)
    {
        progress(info.size, info.size, progressCtx);
    }
    if (info.exists && size != NULL)
    {
        *size = info.size;
    }
    return 0;
}

int ProtocolClient::Put(const SessionOptions & options, const std::string & localPath,
    const std::string & remotePath, int permissions, unsigned long long resumeOffset,
    bool preserveTime, unsigned long long * size, LscpProgressFn progress,
    void * progressCtx, std::string & error, unsigned speedKBytesPerSecond)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::Put(options, localPath, remotePath, permissions,
            resumeOffset, preserveTime, size, progress, progressCtx, error,
            speedKBytesPerSecond);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::Put(options, localPath, remotePath, permissions,
            resumeOffset, preserveTime, size, progress, progressCtx, error,
            speedKBytesPerSecond);
    }
    (void)permissions;
    if (size != NULL)
    {
        *size = 0;
    }

    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args, true, progress != NULL);

    if (resumeOffset > 0)
    {
        args.push_back("-C");
        args.push_back(std::to_string(resumeOffset));
    }

    if (preserveTime)
    {
        /* -R gives the uploaded file the local file's modification
         * time where the protocol supports it (FTP MFMT, SFTP). */
        args.push_back("-R");
    }

    if (speedKBytesPerSecond > 0)
    {
        args.push_back("--limit-rate");
        args.push_back(std::to_string(speedKBytesPerSecond) + "k");
    }

    /* A locked path: the token proves this writer owns the lock, and a
     * lock that expired or was broken makes the server refuse the
     * upload (412) instead of writing over somebody else's change.
     * ETag preconditions (If-Match/If-None-Match) are added alongside
     * the lock token in the If header. */
    const std::string davIfHeader = DavIfHeader(options, remotePath);
    if (!davIfHeader.empty())
    {
        args.push_back("-H");
        args.push_back("If: " + davIfHeader);
    }

    args.push_back("-T");
    args.push_back(localPath);
    args.push_back(BuildUrl(options, remotePath));

    std::string outStr;
    std::string errStr;
    int rc = progress != NULL ?
        RunCurlCaptureWithProgress(args, outStr, errStr, progress, progressCtx, true) :
        RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        errStr = CurlErrorWithoutProgress(errStr);
        error = errStr.empty() ? "Upload failed with exit code " + std::to_string(rc) : errStr;
        return -1;
    }

    LocalFileInfo info = StatLocal(localPath);
    if (progress != NULL && info.exists)
    {
        progress(info.size, info.size, progressCtx);
    }
    if (info.exists && size != NULL)
    {
        *size = info.size;
    }
    return 0;
}

int ProtocolClient::Remove(const SessionOptions & options, const std::string & remotePath,
    std::string & error)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::Remove(options, remotePath, error);
    }
    if (FtpClient::Handles(options))
    {
        return FtpClient::Remove(options, remotePath, error);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::Remove(options, remotePath, error);
    }
    if (IsDavProtocol(ToLower(options.protocol)))
    {
        return DavDelete(options, remotePath, false, error);
    }
    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args);

    std::string proto = ToLower(options.protocol);
    if (proto == "ftp" || proto == "ftps")
    {
        args.push_back("-Q");
        args.push_back("DELE " + remotePath);
        args.push_back(BuildUrl(options, "/"));
    }
    else
    {
        args.push_back("-X");
        args.push_back("DELETE");
        args.push_back(BuildUrl(options, remotePath));
    }

    std::string outStr;
    std::string errStr;
    int rc = RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        error = errStr.empty() ? "Remove failed with exit code " + std::to_string(rc) : errStr;
        return -1;
    }
    return 0;
}

int ProtocolClient::RemoveDir(const SessionOptions & options, const std::string & remotePath,
    std::string & error)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::RemoveDir(options, remotePath, error);
    }
    if (FtpClient::Handles(options))
    {
        return FtpClient::RemoveDir(options, remotePath, error);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::RemoveDir(options, remotePath, error);
    }
    if (IsDavProtocol(ToLower(options.protocol)))
    {
        /*
         * A DELETE of a collection removes the whole tree on most DAV
         * servers (RFC 4918 says it must), which is 'rm -r', not 'rmdir':
         * check the children first so an empty directory is the only
         * thing that gets deleted.
         */
        std::vector<ListingEntry> children;
        if (!DavFetchListing(options, remotePath, children, error))
        {
            return -1;
        }
        if (!children.empty())
        {
            error = "The directory is not empty.";
            return -1;
        }
        return DavDelete(options, remotePath, true, error);
    }
    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args);

    std::string proto = ToLower(options.protocol);
    if (proto == "ftp" || proto == "ftps")
    {
        args.push_back("-Q");
        args.push_back("RMD " + remotePath);
        args.push_back(BuildUrl(options, "/"));
    }
    else
    {
        args.push_back("-X");
        args.push_back("DELETE");
        args.push_back(BuildUrl(options, remotePath));
    }

    std::string outStr;
    std::string errStr;
    int rc = RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        error = errStr.empty() ? "Remove directory failed with exit code " + std::to_string(rc) : errStr;
        return -1;
    }
    return 0;
}

int ProtocolClient::MakeDir(const SessionOptions & options, const std::string & remotePath,
    std::string & error)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::MakeDir(options, remotePath, error);
    }
    if (FtpClient::Handles(options))
    {
        return FtpClient::MakeDir(options, remotePath, error);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::MakeDir(options, remotePath, error);
    }
    if (IsDavProtocol(ToLower(options.protocol)))
    {
        /* Does it already exist? (MKCOL's 405 alone would do, but a
         * named 'already exists' beats a raw status for the user.) */
        DavResult probe;
        std::string probeError;
        if (!DavPropfindOnce(options, remotePath, "0", probe, probeError))
        {
            error = probeError;
            return -1;
        }
        if (probe.httpCode == 207 || probe.httpCode == 200)
        {
            error = "Cannot create the directory '" + remotePath +
                "': that name already exists.";
            return -1;
        }
        if (probe.httpCode != 404 && probe.httpCode != 405 &&
            probe.httpCode < 500)
        {
            error = DavHttpFailure(probe, "Create directory");
            return -1;
        }

        DavResult created;
        std::string createError;
        if (!DavInvoke(options, "MKCOL", remotePath,
            std::vector<std::pair<std::string, std::string> >(),
            std::string(), created, createError))
        {
            error = createError;
            return -1;
        }
        if (created.httpCode == 201 || created.httpCode == 204 ||
            created.httpCode == 200)
        {
            return 0;
        }
        if (created.httpCode == 405)
        {
            error = "Cannot create the directory '" + remotePath +
                "': that name already exists.";
            return -1;
        }
        if (created.httpCode == 409)
        {
            error = "Cannot create the directory '" + remotePath +
                "': the parent directory does not exist.";
            return -1;
        }
        error = DavHttpFailure(created, "Create directory");
        return -1;
    }
    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args);

    std::string proto = ToLower(options.protocol);
    if (proto == "ftp" || proto == "ftps")
    {
        args.push_back("-Q");
        args.push_back("MKD " + remotePath);
        args.push_back(BuildUrl(options, "/"));
    }
    else
    {
        args.push_back("-X");
        args.push_back("MKCOL");
        args.push_back(BuildUrl(options, remotePath));
    }

    std::string outStr;
    std::string errStr;
    int rc = RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        error = errStr.empty() ? "Create directory failed with exit code " + std::to_string(rc) : errStr;
        return -1;
    }
    return 0;
}

int ProtocolClient::Copy(const SessionOptions & options,
    const std::string & fromPath, const std::string & toPath,
    std::string & error)
{
    error.clear();
    const std::string proto = ToLower(options.protocol);
    if (ScpClient::Handles(options))
    {
        /* The server's own 'cp' copies without the bytes coming here; a
         * server without one answers 127 and the caller streams instead. */
        return ScpClient::Copy(options, fromPath, toPath, error);
    }
    if (proto == "s3")
    {
        return S3Client::Copy(options, fromPath, toPath, error);
    }
    if (IsDavProtocol(proto))
    {
        std::vector<std::pair<std::string, std::string> > headers;
        headers.push_back(std::make_pair(std::string("Destination"),
            BuildUrl(options, toPath)));
        /* cp overwrites when confirmation was accepted (or disabled), just
         * like the stream-copy fallback's PUT to the destination. */
        headers.push_back(std::make_pair(std::string("Overwrite"),
            std::string("T")));
        DavResult copied;
        std::string copyError;
        if (!DavInvoke(options, "COPY", fromPath, headers, std::string(),
                copied, copyError))
        {
            error = copyError;
            return -1;
        }
        if (copied.httpCode == 200 || copied.httpCode == 201 ||
            copied.httpCode == 204)
        {
            return 0;
        }
        /* COPY is optional in deployed DAV servers. Keep the portable
         * download/upload fallback for servers which explicitly do not
         * implement or permit this method. */
        if (copied.httpCode == 405 || copied.httpCode == 501)
        {
            return 1;
        }
        if (copied.httpCode == 404)
        {
            error = "No such file or directory.";
            return -1;
        }
        if (copied.httpCode == 412)
        {
            error = "The server refused to overwrite the destination '" +
                toPath + "'.";
            return -1;
        }
        error = "Cannot copy '" + fromPath + "': " +
            DavHttpFailure(copied, "Copy");
        return -1;
    }
    return 1;
}

int ProtocolClient::Move(const SessionOptions & options, const std::string & fromPath,
    const std::string & toPath, std::string & error)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::Move(options, fromPath, toPath, error);
    }
    if (FtpClient::Handles(options))
    {
        return FtpClient::Move(options, fromPath, toPath, error);
    }
    if (ToLower(options.protocol) == "s3")
    {
        return S3Client::Move(options, fromPath, toPath, error);
    }
    if (IsDavProtocol(ToLower(options.protocol)))
    {
        std::vector<std::pair<std::string, std::string> > headers;
        /* RFC 4918 wants the Destination as an absolute URI, and
         * Overwrite: T (the default, made explicit) for 'mv' semantics
         * where the destination may already exist. */
        headers.push_back(std::make_pair(std::string("Destination"),
            BuildUrl(options, toPath)));
        headers.push_back(std::make_pair(std::string("Overwrite"),
            std::string("T")));
        DavResult moved;
        std::string moveError;
        const std::string davIfHeader = DavIfHeader(options, fromPath);
        if (!DavInvoke(options, "MOVE", fromPath, headers, std::string(),
            moved, moveError, davIfHeader))
        {
            error = moveError;
            return -1;
        }
        if (moved.httpCode == 201 || moved.httpCode == 204 ||
            moved.httpCode == 200)
        {
            return 0;
        }
        if (moved.httpCode == 404)
        {
            error = "No such file or directory.";
            return -1;
        }
        if (moved.httpCode == 412)
        {
            /* A 412 answers two different questions and only one of them
             * is about the destination: a precondition this session
             * recorded for the source is the server saying the version it
             * has is not the one the move was asked to apply to, which is
             * nothing to do with what sits at the other path. */
            if (options.davEtags.find(fromPath) != options.davEtags.end())
            {
                error = "The server refused to move '" + fromPath +
                    "': the ETag precondition recorded for it does not "
                    "hold any more.";
                return -1;
            }
            error = "The destination '" + toPath +
                "' exists and the server refused to overwrite it.";
            return -1;
        }
        error = "Cannot move '" + fromPath + "': " +
            DavHttpFailure(moved, "Move");
        return -1;
    }
    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args);

    std::string proto = ToLower(options.protocol);
    if (proto == "ftp" || proto == "ftps")
    {
        args.push_back("-Q");
        args.push_back("RNFR " + fromPath);
        args.push_back("-Q");
        args.push_back("RNTO " + toPath);
        args.push_back(BuildUrl(options, "/"));
    }
    else
    {
        args.push_back("-X");
        args.push_back("MOVE");
        args.push_back("-H");
        args.push_back("Destination: " + toPath);
        args.push_back(BuildUrl(options, fromPath));
    }

    std::string outStr;
    std::string errStr;
    int rc = RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        error = errStr.empty() ? "Move failed with exit code " + std::to_string(rc) : errStr;
        return -1;
    }
    return 0;
}

int ProtocolClient::SetPermissions(const SessionOptions & options,
    const std::string & remotePath, int permissions, std::string & error)
{
    if (ScpClient::Handles(options))
    {
        return ScpClient::SetPermissions(options, remotePath, permissions, error);
    }
    if (FtpClient::Handles(options))
    {
        return FtpClient::SetPermissions(options, remotePath, permissions, error);
    }
    std::vector<std::string> args;
    BuildCommonCurlArgs(options, args);

    std::string proto = ToLower(options.protocol);
    if (proto == "ftp" || proto == "ftps")
    {
        args.push_back("-Q");
        args.push_back("SITE CHMOD " + OctalPermissions(permissions) + " " + remotePath);
        args.push_back(BuildUrl(options, "/"));
    }
    else if (proto == "sftp")
    {
        args.push_back("-Q");
        args.push_back("chmod " + OctalPermissions(permissions) + " " + remotePath);
        args.push_back(BuildUrl(options, "/"));
    }
    else
    {
        error = "chmod is not supported by the " + options.protocol + " protocol.";
        return -1;
    }

    std::string outStr;
    std::string errStr;
    int rc = RunCurl(args, outStr, errStr);
    if (rc != 0)
    {
        error = errStr.empty() ? "Change permissions failed with exit code " +
            std::to_string(rc) : errStr;
        return -1;
    }
    return 0;
}


/*
 * The token of a LOCK reply. Servers answer with a lockdiscovery body
 * ('...<locktoken><href>opaquelocktoken:...</href></locktoken>...'), and a
 * few send the token on its own, so both are accepted and anything else
 * (including a reply with no token at all) is a failure: without a token
 * the lock cannot be released or used.
 */
bool DavLockTokenFromXml(const std::string & xml, std::string & token)
{
    token.clear();
    const std::string key = "locktoken";
    const size_t at = xml.find(key);
    if (at == std::string::npos)
    {
        const std::string text = DavTrimmed(xml);
        if (!text.empty() && text.find('<') == std::string::npos)
        {
            token = text;
            return true;
        }
        return false;
    }
    size_t cursor = xml.find('>', at + key.size());
    if (cursor == std::string::npos)
    {
        return false;
    }
    const size_t textStart = xml.find('>', cursor + 1);
    if (textStart == std::string::npos)
    {
        return false;
    }
    const size_t end = xml.find('<', textStart + 1);
    if (end == std::string::npos)
    {
        return false;
    }
    token = DavTrimmed(DavXmlUnescape(
        xml.substr(textStart + 1, end - textStart - 1)));
    return !token.empty();
}

/* An XML element name has to start with a letter or '_' and hold no
 * whitespace or markup; anything else would build a request the server
 * cannot parse, which would look like a server failure. */
bool DavValidPropertyName(const std::string & name, std::string & error)
{
    if (name.empty())
    {
        error = "The property name is empty.";
        return false;
    }
    const char first = name[0];
    if (!(isalpha(static_cast<unsigned char>(first)) || first == '_'))
    {
        error = "The property name '" + name + "' has to start with a letter "
            "or '_'.";
        return false;
    }
    for (size_t i = 1; i < name.size(); i++)
    {
        const char c = name[i];
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' ||
            c == '.'))
        {
            error = "The property name '" + name + "' may only hold letters, "
                "digits, '_', '-' and '.'.";
            return false;
        }
    }
    return true;
}

std::string DavPropertyPropfindBody(const std::string & name)
{
    return std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?>") +
        "<D:propfind xmlns:D=\"DAV:\" xmlns:" + kDavPropertyPrefix + "=\"" +
        kDavPropertyNamespace + "\"><D:prop><" + kDavPropertyPrefix + ":" +
        name + "/></D:prop></D:propfind>";
}

/*
 * The value of a dead property in a PROPFIND answer, and whether the
 * server carried it. A 404 propstat (the property is not set) is 'found'
 * false, which is an answer and not an error; the element's text is the
 * value, so an empty element means the property is set to "".
 */
bool DavPropertyValueFromXml(const std::string & xml, const std::string & name,
    std::string & value, bool & found)
{
    value.clear();
    found = false;
    if (!DavFindText(xml, name, 0, value))
    {
        return false;
    }
    found = true;
    return true;
}

/* LOCK one path with an exclusive write lock and return its token. */
bool ProtocolClient::DavLock(const SessionOptions & options,
    const std::string & remotePath, int timeoutSeconds, std::string & token,
    std::string & error)
{
    token.clear();
    if (!IsDavProtocol(options.protocol))
    {
        error = "Locks are a WebDAV feature; this session is " +
            options.protocol + ".";
        return false;
    }
    std::vector<std::pair<std::string, std::string> > headers;
    headers.push_back(std::make_pair(std::string("Depth"), std::string("0")));
    headers.push_back(std::make_pair(std::string("Timeout"),
        timeoutSeconds > 0 ? ("Second-" + std::to_string(timeoutSeconds)) :
            std::string("Infinite")));
    headers.push_back(std::make_pair(std::string("Content-Type"),
        std::string("application/xml")));
    const std::string body =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<lockinfo xmlns=\"DAV:\"><lockscope><exclusive/></lockscope>"
        "<locktype><write/></locktype>"
        "<owner><href>linscp</href></owner></lockinfo>";
    DavResult result;
    if (!DavInvoke(options, "LOCK", remotePath, headers, body, result, error))
    {
        return false;
    }
    if (result.httpCode != 200 && result.httpCode != 201)
    {
        error = result.httpCode == 405 ?
            "The WebDAV server does not implement LOCK." :
            DavHttpFailure(result, "Lock");
        return false;
    }
    if (!DavLockTokenFromXml(result.out, token))
    {
        error = "The server's LOCK reply carried no lock token.";
        return false;
    }
    return true;
}

/* UNLOCK the path with the token the LOCK returned. The token is the
 * proof of ownership, so a lock taken by somebody else cannot be
 * released and the server answers 409 or 403 instead. */
bool ProtocolClient::DavUnlock(const SessionOptions & options,
    const std::string & remotePath, const std::string & token, std::string & error)
{
    if (!IsDavProtocol(options.protocol))
    {
        error = "Locks are a WebDAV feature; this session is " +
            options.protocol + ".";
        return false;
    }
    if (token.empty())
    {
        error = "There is no lock token to release.";
        return false;
    }
    std::vector<std::pair<std::string, std::string> > headers;
    headers.push_back(std::make_pair(std::string("Lock-Token"),
        "<" + token + ">"));
    DavResult result;
    if (!DavInvoke(options, "UNLOCK", remotePath, headers, std::string(),
        result, error))
    {
        return false;
    }
    if (result.httpCode != 204 && result.httpCode != 200)
    {
        error = result.httpCode == 405 ?
            "The WebDAV server does not implement UNLOCK." :
            DavHttpFailure(result, "Unlock");
        return false;
    }
    return true;
}

/* PROPPATCH one dead property in this client's own namespace, so that a
 * protected property (getlastmodified and friends) is never the target
 * and the value a client stores cannot be confused with the server's. */
bool ProtocolClient::DavSetProperty(const SessionOptions & options,
    const std::string & remotePath, const std::string & name,
    const std::string & value, std::string & error)
{
    if (!IsDavProtocol(options.protocol))
    {
        error = "Dead properties are a WebDAV feature; this session is " +
            options.protocol + ".";
        return false;
    }
    std::string nameError;
    if (!DavValidPropertyName(name, nameError))
    {
        error = nameError;
        return false;
    }
    std::vector<std::pair<std::string, std::string> > headers;
    headers.push_back(std::make_pair(std::string("Content-Type"),
        std::string("application/xml")));
    DavResult result;
    if (!DavInvoke(options, "PROPPATCH", remotePath, headers,
        DavPropertyUpdateBody(name, value), result, error))
    {
        return false;
    }
    if (result.httpCode != 207 && result.httpCode != 200)
    {
        error = result.httpCode == 405 ?
            "The WebDAV server does not implement PROPPATCH." :
            DavHttpFailure(result, "Set property");
        return false;
    }
    /* A 207 can still hold a refused property: the server answers one
     * propstat per property it was asked about. */
    const std::string refusal = DavMultiStatusFailure(result.out);
    if (!refusal.empty())
    {
        error = "The server refused to store '" + name + "': " + refusal;
        return false;
    }
    return true;
}

/* PROPFIND one dead property of one path. 'found' false means the server
 * answered a 404 propstat: the property is not set, which is an answer. */
bool ProtocolClient::DavGetProperty(const SessionOptions & options,
    const std::string & remotePath, const std::string & name,
    std::string & value, bool & found, std::string & error)
{
    value.clear();
    found = false;
    if (!IsDavProtocol(options.protocol))
    {
        error = "Dead properties are a WebDAV feature; this session is " +
            options.protocol + ".";
        return false;
    }
    std::string nameError;
    if (!DavValidPropertyName(name, nameError))
    {
        error = nameError;
        return false;
    }
    std::vector<std::pair<std::string, std::string> > headers;
    headers.push_back(std::make_pair(std::string("Depth"), std::string("0")));
    headers.push_back(std::make_pair(std::string("Content-Type"),
        std::string("application/xml")));
    DavResult result;
    if (!DavInvoke(options, "PROPFIND", remotePath, headers,
        DavPropertyPropfindBody(name), result, error))
    {
        return false;
    }
    if (result.httpCode != 207 && result.httpCode != 200)
    {
        error = DavHttpFailure(result, "Get property");
        return false;
    }
    DavPropertyValueFromXml(result.out, name, value, found);
    return true;
}

/* Retrieve the current ETag of a resource via a Depth-0 PROPFIND.
 * Returns false with etag empty when the path does not exist. */
bool ProtocolClient::DavGetEtag(const SessionOptions & options,
    const std::string & remotePath, std::string & etag,
    bool & pathMissing, std::string & error)
{
    etag.clear();
    pathMissing = false;
    if (!IsDavProtocol(options.protocol))
    {
        error = "ETags are a WebDAV feature; this session is " +
            options.protocol + ".";
        return false;
    }
    const std::string body =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<propfind xmlns=\"DAV:\"><prop><getetag/></prop></propfind>";
    std::vector<std::pair<std::string, std::string> > headers;
    headers.push_back(std::make_pair(std::string("Depth"), std::string("0")));
    headers.push_back(std::make_pair(std::string("Content-Type"),
        std::string("application/xml")));
    DavResult result;
    if (!DavInvoke(options, "PROPFIND", remotePath, headers, body,
        result, error))
    {
        return false;
    }
    if (result.httpCode == 404)
    {
        /* The resource does not exist; etag stays empty and the caller
         * says so rather than reporting a server that sent nothing. */
        pathMissing = true;
        return true;
    }
    if (result.httpCode != 207 && result.httpCode != 200)
    {
        error = DavHttpFailure(result, "Get ETag");
        return false;
    }
    /* Parse the ETag from the multi-status response.  The XML uses
     * getetag inside a propstat, like:
     *   <D:getetag>"abc123"</D:getetag>
     * The value may be wrapped in double quotes (the HTTP convention) and
     * we preserve whatever the server returns. */
    std::vector<DavResponse> responses;
    std::string parseError;
    DavParseMultiStatus(result.out, responses, parseError);
    if (!responses.empty())
    {
        etag = responses[0].etag;
    }
    return true;
}

std::string DavPropertyUpdateBody(const std::string & name,
    const std::string & value)
{
    return std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?>") +
        "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:" + kDavPropertyPrefix +
        "=\"" + kDavPropertyNamespace + "\"><D:set><D:prop><" +
        kDavPropertyPrefix + ":" + name + ">" + DavXmlEscape(value) + "</" +
        kDavPropertyPrefix + ":" + name + "></D:prop></D:set></D:propertyupdate>";
}

} // namespace linscp
