/*
 * SshKeys: see SshKeys.h.
 */

#include "SshKeys.h"

#include "PathUtil.h"
#include "Platform.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <vector>

#include <libssh/libssh.h>

namespace linscp {

namespace {

std::string HostKeyPath()
{
    return ConfigDirectory() + "/sshhostkeys";
}

std::string HostKeyPrefix(const char * hostname, int port)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%d", port);
    return std::string(hostname) + "@" + buffer;
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
    std::vector<std::string> lines;
    ReadLines(HostKeyPath(), lines);
    const std::string prefix = HostKeyPrefix(hostname, port);
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string type;
        std::string value;
        if (!ParseHostKeyLine(lines[i], prefix, type, value))
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
    if (ConfigDirectory().empty())
    {
        return;
    }
    EnsureConfigDirectory();
    std::vector<std::string> lines;
    ReadLines(HostKeyPath(), lines);
    std::string prefix = HostKeyPrefix(hostname, port);
    std::string entry = prefix + " " + keytype + " " + key;
    bool replaced = false;
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string type;
        std::string value;
        if (ParseHostKeyLine(lines[i], prefix, type, value) && type == keytype)
        {
            lines[i] = entry;
            replaced = true;
        }
    }
    if (!replaced)
    {
        lines.push_back(entry);
    }
    std::ofstream out(HostKeyPath().c_str(), std::ios::trunc);
    if (!out)
    {
        return;
    }
    for (size_t i = 0; i < lines.size(); i++)
    {
        out << lines[i] << "\n";
    }
}

bool IsPuttyKeyFile(const std::string & keyFile)
{
    if (keyFile.size() < 4)
    {
        return false;
    }
    std::string extension = keyFile.substr(keyFile.size() - 4);
    for (size_t i = 0; i < extension.size(); i++)
    {
        extension[i] = static_cast<char>(
            tolower(static_cast<unsigned char>(extension[i])));
    }
    return extension == ".ppk";
}

bool PublicKeyAuthorizedLine(const std::string & keyFile, std::string & line,
    std::string & error, const std::string & suppliedPassphrase)
{
    line.clear();
    error.clear();
    if (IsPuttyKeyFile(keyFile))
    {
        error = "The PuTTY key file '" + keyFile + "' cannot be read by "
            "this build; convert it to an OpenSSH key first, for example "
            "with 'puttygen " + keyFile + " -O private-openssh'.";
        return false;
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
    if (ssh_pki_export_pubkey_base64(key, &base64) != SSH_OK)
    {
        ssh_key_free(key);
        error = "Cannot export the public key of '" + keyFile + "'.";
        return false;
    }
    line = std::string(ssh_key_type_to_char(ssh_key_type(key))) + " " + base64;
    ssh_string_free_char(base64);
    ssh_key_free(key);
    return true;
}

} // namespace linscp
