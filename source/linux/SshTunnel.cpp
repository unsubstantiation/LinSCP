/*
 * SshTunnel: SSH port-forwarding and GSSAPI detection.
 */

#include "SshTunnel.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include <unistd.h>

#include "Platform.h"

namespace linscp {

namespace {

/*
 * One port number out of a tunnel specification.
 *
 * atoi() was used here before: it stops at the first character that is
 * not a digit and returns 0 for text, so 'localhost:80x' parsed as 80 and
 * an overflowed '99999999999999' was undefined behaviour rather than an
 * error. A tunnel that binds the wrong port is not something to be
 * approximate about, so the whole field has to be digits and in range.
 */
bool ParsePort(const std::string & text, int & port)
{
    if (text.empty() || text.size() > 5)
    {
        return false;
    }
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] < '0' || text[i] > '9')
        {
            return false;
        }
    }
    const long value = strtol(text.c_str(), NULL, 10);
    if (value < 1 || value > 65535)
    {
        return false;
    }
    port = static_cast<int>(value);
    return true;
}

#ifndef NO_GSSAPI
/*
 * Whether a shared object the dynamic linker would find is installed.
 *
 * Libraries live in the loader's directories, not on PATH, and are not
 * marked executable, so searching PATH for one never found it and
 * GSSAPI reported itself missing on a system that had it. Only built
 * where it can be reached: this build compiles GSSAPI out.
 */
bool SharedObjectInstalled(const char * soname)
{
    static const char * const dirs[] = {
        "/lib", "/usr/lib", "/lib64", "/usr/lib64",
        "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
        "/lib/i386-linux-gnu", "/usr/lib/i386-linux-gnu"
    };
    const char * extra = getenv("LD_LIBRARY_PATH");
    std::string searchDirs;
    if (extra != NULL)
    {
        searchDirs = extra;
    }
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
    {
        const std::string candidate = std::string(dirs[i]) + "/" + soname;
        if (access(candidate.c_str(), R_OK) == 0)
        {
            return true;
        }
    }
    size_t start = 0;
    while (start <= searchDirs.size())
    {
        const size_t colon = searchDirs.find(':', start);
        const std::string dir = searchDirs.substr(start,
            colon == std::string::npos ? colon : colon - start);
        if (!dir.empty())
        {
            const std::string candidate = dir + "/" + soname;
            if (access(candidate.c_str(), R_OK) == 0)
            {
                return true;
            }
        }
        if (colon == std::string::npos)
        {
            break;
        }
        start = colon + 1;
    }
    return false;
}
#endif /* NO_GSSAPI */

} // namespace

bool ParseTunnelSpec(const std::string & spec, TunnelType type,
    SshTunnel & tunnel, std::string & error)
{
    tunnel.type = type;
    tunnel.bindAddress.clear();
    tunnel.bindPort = 0;
    tunnel.remoteHost.clear();
    tunnel.remotePort = 0;

    if (spec.empty())
    {
        error = "Empty tunnel specification.";
        return false;
    }

    /* Split on colons.  The formats are:
     *   port:host:hostport    (local/remote)
     *   bind:port:host:hostport (local/remote with bind)
     *   port                  (dynamic)
     *   bind:port             (dynamic with bind) */
    std::vector<std::string> parts;
    std::istringstream stream(spec);
    std::string part;
    while (std::getline(stream, part, ':'))
    {
        parts.push_back(part);
    }

    if (type == TunnelType::Dynamic)
    {
        if (parts.size() == 1)
        {
            if (!ParsePort(parts[0], tunnel.bindPort))
            {
                error = "Dynamic tunnel format: [bind_address:]port, with a "
                    "port from 1 to 65535.";
                return false;
            }
        }
        else if (parts.size() == 2)
        {
            tunnel.bindAddress = parts[0];
            if (!ParsePort(parts[1], tunnel.bindPort))
            {
                error = "Dynamic tunnel format: [bind_address:]port, with a "
                    "port from 1 to 65535.";
                return false;
            }
        }
        else
        {
            error = "Dynamic tunnel format: [bind_address:]port";
            return false;
        }
    }
    else
    {
        if (parts.size() == 3)
        {
            if (!ParsePort(parts[0], tunnel.bindPort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
            tunnel.remoteHost = parts[1];
            if (!ParsePort(parts[2], tunnel.remotePort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
        }
        else if (parts.size() == 4)
        {
            tunnel.bindAddress = parts[0];
            if (!ParsePort(parts[1], tunnel.bindPort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
            tunnel.remoteHost = parts[2];
            if (!ParsePort(parts[3], tunnel.remotePort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
        }
        else
        {
            error = "Tunnel format: [bind_address:]port:host:hostport";
            return false;
        }
    }

    if (tunnel.bindPort <= 0 || tunnel.bindPort > 65535)
    {
        error = "Bind port out of range (1-65535).";
        return false;
    }
    if (type != TunnelType::Dynamic)
    {
        if (tunnel.remoteHost.empty())
        {
            error = "Remote host is required for local/remote tunnels.";
            return false;
        }
        if (tunnel.remotePort <= 0 || tunnel.remotePort > 65535)
        {
            error = "Remote port out of range (1-65535).";
            return false;
        }
    }
    return true;
}

std::string TunnelSshFlags(const SshTunnel & tunnel)
{
    std::string flag;
    switch (tunnel.type)
    {
    case TunnelType::Local:   flag = "-L"; break;
    case TunnelType::Remote:  flag = "-R"; break;
    case TunnelType::Dynamic: flag = "-D"; break;
    }
    std::string spec;
    if (!tunnel.bindAddress.empty())
    {
        spec = tunnel.bindAddress + ":";
    }
    spec += std::to_string(tunnel.bindPort);
    if (tunnel.type != TunnelType::Dynamic)
    {
        spec += ":" + tunnel.remoteHost + ":" + std::to_string(tunnel.remotePort);
    }
    return flag + " " + spec;
}

bool IsGssapiSupported()
{
#ifdef NO_GSSAPI
    return false;
#else
    /* Runtime check: the Kerberos library has to be where the dynamic
     * linker looks, not on PATH, and it does not have to be executable. */
    return SharedObjectInstalled("libgssapi_krb5.so.2");
#endif
}

bool ApplyGssapiSetting(const std::string & value, std::string & error)
{
    (void)value;
    if (!IsGssapiSupported())
    {
        error = "GSSAPI/Kerberos is not available in this build. "
            "Install libgssapi-krb5-2 and rebuild with -DNO_GSSAPI removed "
            "to enable it.";
        return false;
    }
    /* When the build enables libssh GSSAPI support, libssh handles the
     * authentication exchange. This setting only validates the request. */
    return true;
}

} // namespace linscp