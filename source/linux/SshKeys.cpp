/*
 * SshKeys: see SshKeys.h.
 */

#include "SshKeys.h"

#include "PpkKey.h"
#include "PathUtil.h"
#include "Platform.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <libssh/libssh.h>

namespace linscp {

namespace {

std::string HostKeyPath()
{
    return ConfigDirectory() + "/sshhostkeys";
}

bool HasInvalidHostKeyFieldChars(const char * text)
{
    if (text == NULL || text[0] == '\0')
    {
        return true;
    }
    for (const char * p = text; *p != '\0'; ++p)
    {
        const unsigned char c = static_cast<unsigned char>(*p);
        if (c <= 0x20 || c == 0x7f)
        {
            return true;
        }
    }
    return false;
}

std::string LowerHost(const char * hostname)
{
    if (hostname == NULL)
    {
        return std::string();
    }
    std::string result(hostname);
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = static_cast<char>(
            std::tolower(static_cast<unsigned char>(result[i])));
    }
    return result;
}

std::string HostKeyPrefix(const char * hostname, int port)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%d", port);
    return LowerHost(hostname) + "@" + buffer;
}

bool ReadLines(const std::string & path, std::vector<std::string> & lines)
{
    std::ifstream in(path.c_str());
    if (!in)
    {
        return false;
    }
    std::string line;
    while (std::getline(in, line))
    {
        if (!line.empty() && line[line.size() - 1] == '\r')
        {
            line.erase(line.size() - 1);
        }
        lines.push_back(line);
    }
    return true;
}

/*
 * Parses a cache line, which reads
 *
 *     <hostname>@<port> <key type> <key>
 *
 * where <key> may itself contain no spaces but is otherwise opaque.
 * Returns false for a line that does not belong to this host and port
 * ('example.com@22' must not match a line for 'example.com@222'), or one
 * that is malformed.
 */
bool ParseHostKeyLine(const std::string & line, const std::string & prefix,
    std::string & type, std::string & value)
{
    if (line.size() <= prefix.size() ||
        line.compare(0, prefix.size(), prefix) != 0 ||
        (line[prefix.size()] != ' ' && line[prefix.size()] != '\t'))
    {
        return false;
    }
    const std::string::size_type typeStart =
        line.find_first_not_of(" \t", prefix.size());
    if (typeStart == std::string::npos)
    {
        return false;
    }
    const std::string::size_type typeEnd =
        line.find_first_of(" \t", typeStart);
    if (typeEnd == std::string::npos)
    {
        return false;
    }
    const std::string::size_type valueStart =
        line.find_first_not_of(" \t", typeEnd);
    if (valueStart == std::string::npos)
    {
        return false;
    }
    type = line.substr(typeStart, typeEnd - typeStart);
    value = line.substr(valueStart);
    return true;
}

void EnsureConfigDirectory()
{
    const std::string dir = ConfigDirectory();
    if (dir.empty())
    {
        return;
    }
    std::string built;
    for (size_t i = 0; i < dir.size(); i++)
    {
        built += dir[i];
        if (dir[i] == '/' && i > 0)
        {
            mkdir(built.c_str(), 0700);
        }
    }
    mkdir(dir.c_str(), 0700);
}

} // namespace

int CheckCachedHostKey(const char * hostname, int port,
    const char * keytype, const char * key)
{
    if (hostname == NULL || hostname[0] == '\0')
    {
        return 0;
    }
    std::vector<std::string> lines;
    ReadLines(HostKeyPath(), lines);
    const std::string lowerPrefix = HostKeyPrefix(hostname, port);
    char portBuf[32];
    snprintf(portBuf, sizeof(portBuf), "%d", port);
    const std::string rawPrefix = std::string(hostname) + "@" + portBuf;
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string type;
        std::string value;
        if (!ParseHostKeyLine(lines[i], lowerPrefix, type, value) &&
            (rawPrefix == lowerPrefix ||
             !ParseHostKeyLine(lines[i], rawPrefix, type, value)))
        {
            continue;
        }
        if (keytype != NULL && type != keytype)
        {
            continue;
        }
        return (key != NULL && value == key) ? 1 : -1;
    }
    return 0;
}

void StoreHostKey(const char * hostname, int port,
    const char * keytype, const char * key)
{
    if (ConfigDirectory().empty() ||
        HasInvalidHostKeyFieldChars(hostname) ||
        HasInvalidHostKeyFieldChars(keytype) ||
        HasInvalidHostKeyFieldChars(key))
    {
        return;
    }
    EnsureConfigDirectory();
    const std::string path = HostKeyPath();
    std::vector<std::string> lines;
    ReadLines(path, lines);
    const std::string prefix = HostKeyPrefix(hostname, port);
    char portBuf[32];
    snprintf(portBuf, sizeof(portBuf), "%d", port);
    const std::string rawPrefix = std::string(hostname) + "@" + portBuf;
    const std::string entry = prefix + " " + keytype + " " + key;
    bool replaced = false;
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string type;
        std::string value;
        if ((ParseHostKeyLine(lines[i], prefix, type, value) ||
             (rawPrefix != prefix &&
              ParseHostKeyLine(lines[i], rawPrefix, type, value))) &&
            type == keytype)
        {
            lines[i] = entry;
            replaced = true;
        }
    }
    if (!replaced)
    {
        lines.push_back(entry);
    }
    std::string tempPattern = path + ".tmp.XXXXXX";
    std::vector<char> tempBuf(tempPattern.begin(), tempPattern.end());
    tempBuf.push_back('\0');
    const int fd = mkstemp(tempBuf.data());
    if (fd < 0)
    {
        return;
    }
    (void)fchmod(fd, 0600);
    const std::string tempPath(tempBuf.data());
    close(fd);
    std::ofstream out(tempPath.c_str(), std::ios::trunc);
    if (!out)
    {
        remove(tempPath.c_str());
        return;
    }
    for (size_t i = 0; i < lines.size(); i++)
    {
        out << lines[i] << "\n";
    }
    out.flush();
    if (!out.good())
    {
        out.close();
        remove(tempPath.c_str());
        return;
    }
    out.close();
    if (rename(tempPath.c_str(), path.c_str()) != 0)
    {
        remove(tempPath.c_str());
        return;
    }
    (void)chmod(path.c_str(), 0600);
}

bool PublicKeyAuthorizedLine(const std::string & keyFile, std::string & line,
    std::string & error, const std::string & suppliedPassphrase)
{
    line.clear();
    error.clear();
    if (IsPpkKeyFile(keyFile))
    {
        return PpkPublicAuthorizedLine(keyFile, suppliedPassphrase, line, error);
    }

    ssh_key key = NULL;
    /* A public key file first: 'copyid id_ed25519.pub' is the common case. */
    if (ssh_pki_import_pubkey_file(keyFile.c_str(), &key) != SSH_OK)
    {
        const char * passphrase = suppliedPassphrase.empty() ?
            NULL : suppliedPassphrase.c_str();
        if (ssh_pki_import_privkey_file(keyFile.c_str(), passphrase,
                NULL, NULL, &key) != SSH_OK)
        {
            error = "Cannot read a usable SSH-2 key from '" + keyFile + "'.";
            return false;
        }
    }

    char * base64 = NULL;
    const char * keyType = ssh_key_type_to_char(ssh_key_type(key));
    if (keyType == NULL ||
        ssh_pki_export_pubkey_base64(key, &base64) != SSH_OK ||
        base64 == NULL)
    {
        if (base64 != NULL)
        {
            ssh_string_free_char(base64);
        }
        ssh_key_free(key);
        error = "Cannot export the public key of '" + keyFile + "'.";
        return false;
    }
    line = std::string(keyType) + " " + base64;
    ssh_string_free_char(base64);
    ssh_key_free(key);
    return true;
}

} // namespace linscp
