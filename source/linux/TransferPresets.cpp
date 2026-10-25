#include "TransferPresets.h"

#include "PathUtil.h"
#include "Platform.h"
#include "Script.h"

#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include <sys/stat.h>
#include <unistd.h>

namespace linscp {

namespace {

std::string TrimCopy(const std::string & text)
{
    size_t begin = 0;
    while (begin < text.size() &&
        (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '\r'))
    {
        begin++;
    }
    size_t end = text.size();
    while (end > begin &&
        (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r'))
    {
        end--;
    }
    return text.substr(begin, end - begin);
}

std::string LowerCopy(const std::string & text)
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

std::string TrimQuotes(const std::string & text)
{
    if (text.size() >= 2 &&
        ((text[0] == '"' && text[text.size() - 1] == '"') ||
         (text[0] == '\'' && text[text.size() - 1] == '\'')))
    {
        return text.substr(1, text.size() - 2);
    }
    return text;
}

bool ParseOnOff(const std::string & text, bool & value)
{
    const std::string v = LowerCopy(TrimCopy(text));
    if (v == "on" || v == "1" || v == "true" || v == "yes")
    {
        value = true;
        return true;
    }
    if (v == "off" || v == "0" || v == "false" || v == "no")
    {
        value = false;
        return true;
    }
    return false;
}

bool ParseLong(const std::string & text, long long & value)
{
    if (text.empty())
    {
        return false;
    }
    char * end = NULL;
    errno = 0;
    const long long parsed = strtoll(text.c_str(), &end, 10);
    if (errno == ERANGE || end == NULL || end == text.c_str() || *end != '\0')
    {
        return false;
    }
    value = parsed;
    return true;
}

std::string StripHostAndPort(const std::string & value)
{
    std::string trimmed = TrimCopy(value);
    if (trimmed.empty())
    {
        return trimmed;
    }
    if (trimmed[0] == '[')
    {
        const size_t close = trimmed.find(']');
        if (close != std::string::npos)
        {
            return trimmed.substr(1, close - 1);
        }
    }
    const size_t colon = trimmed.rfind(':');
    if (colon != std::string::npos && trimmed.find(':') == colon)
    {
        bool portDigits = colon + 1 < trimmed.size();
        for (size_t i = colon + 1; portDigits && i < trimmed.size(); i++)
        {
            portDigits = std::isdigit(static_cast<unsigned char>(trimmed[i])) != 0;
        }
        if (portDigits)
        {
            return trimmed.substr(0, colon);
        }
    }
    return trimmed;
}

/* 'host:port' or '[v6]:port' against the stored host rule, where the
 * rule may itself carry a port, wildcard, domain suffix ('.example.com'),
 * or short hostname ('dev' matching 'dev.corp.example' on a label boundary). */
bool HostRuleMatches(const std::string & rule, const std::string & host)
{
    if (rule.empty())
    {
        return true;
    }
    const std::string ruleHost = LowerCopy(StripHostAndPort(rule));
    const std::string connHost = LowerCopy(StripHostAndPort(host));
    if (ruleHost.empty() || connHost.empty())
    {
        return false;
    }
    if (ruleHost.find_first_of("*?") != std::string::npos)
    {
        return MatchesMask(ruleHost, connHost);
    }
    if (ruleHost[0] == '.')
    {
        const std::string bare = ruleHost.substr(1);
        if (connHost == bare)
        {
            return true;
        }
        return connHost.size() > ruleHost.size() &&
            connHost.compare(connHost.size() - ruleHost.size(),
                ruleHost.size(), ruleHost) == 0;
    }
    if (ruleHost == connHost)
    {
        return true;
    }
    /* A short hostname ('dev') matches 'dev.corp.example' at a '.' label
     * boundary, never an IPv4 prefix ('10.0.0.1' vs '10.0.0.100') or an
     * unrelated prefix ('dev' vs 'devops.corp.example'). */
    if (ruleHost.find('.') == std::string::npos &&
        ruleHost.find(':') == std::string::npos &&
        connHost.size() > ruleHost.size() &&
        connHost.compare(0, ruleHost.size(), ruleHost) == 0 &&
        connHost[ruleHost.size()] == '.')
    {
        return true;
    }
    return false;
}

bool PresetMaskListMatches(const std::string & listText,
    const std::string & leaf, const std::string & full)
{
    size_t pos = 0;
    while (pos <= listText.size())
    {
        const size_t semi = listText.find(';', pos);
        const std::string token = TrimCopy(semi == std::string::npos ?
            listText.substr(pos) : listText.substr(pos, semi - pos));
        if (!token.empty())
        {
            const bool hasSlash = token.find('/') != std::string::npos;
            if (MatchesMask(token, hasSlash ? full : leaf))
            {
                return true;
            }
        }
        if (semi == std::string::npos)
        {
            break;
        }
        pos = semi + 1;
    }
    return false;
}

bool PresetFileMaskMatches(const std::string & mask, const std::string & fileName)
{
    if (mask.empty() || fileName.empty())
    {
        return false;
    }
    std::string leaf = fileName;
    const size_t slash = leaf.find_last_of("/\\");
    if (slash != std::string::npos)
    {
        leaf = leaf.substr(slash + 1);
    }
    if (leaf.empty())
    {
        return false;
    }
    const size_t bar = mask.find('|');
    const std::string includes = TrimCopy(bar == std::string::npos ?
        mask : mask.substr(0, bar));
    const std::string excludes = bar == std::string::npos ?
        std::string() : TrimCopy(mask.substr(bar + 1));
    if (!excludes.empty() && PresetMaskListMatches(excludes, leaf, fileName))
    {
        return false;
    }
    if (includes.empty())
    {
        return !excludes.empty();
    }
    return PresetMaskListMatches(includes, leaf, fileName);
}

bool FieldMatches(const std::string & rule, const std::string & value)
{
    if (rule.empty())
    {
        return true;
    }
    if (value.empty())
    {
        return false;
    }
    return LowerCopy(rule) == LowerCopy(value);
}

} // namespace

bool TransferPreset::HasSessionRule() const
{
    return !host.empty() || !userName.empty() ||
        !remoteDirectory.empty() || !localDirectory.empty();
}

void TransferPreset::ApplyTo(TransferFlags & flags) const
{
    if (transferMode == 0)
    {
        flags.transferMode = TransferMode::Binary;
    }
    else if (transferMode == 1)
    {
        flags.transferMode = TransferMode::Ascii;
    }
    else if (transferMode == 2)
    {
        flags.transferMode = TransferMode::Automatic;
    }
    if (preserveTime >= 0)
    {
        flags.preserveTime = preserveTime != 0;
    }
    if (preserveTimeDirs >= 0)
    {
        flags.preserveTimeDirs = preserveTimeDirs != 0;
    }
    if (newerOnly >= 0)
    {
        flags.newerOnly = newerOnly != 0;
    }
    if (permissions >= -2)
    {
        flags.permissions = permissions;
    }
    if (resumeSupport == 0)
    {
        flags.resumeSupport = TransferFlags::ResumeOn;
    }
    else if (resumeSupport == 1)
    {
        flags.resumeSupport = TransferFlags::ResumeSmart;
    }
    else if (resumeSupport == 2)
    {
        flags.resumeSupport = TransferFlags::ResumeOff;
    }
    if (resumeThreshold >= 0)
    {
        flags.resumeThreshold = static_cast<unsigned long long>(resumeThreshold);
    }
    if (speedLimit >= 0)
    {
        flags.speedKBytesPerSecond = speedLimit > static_cast<long long>(UINT_MAX) ?
            UINT_MAX : static_cast<unsigned>(speedLimit);
    }
}

std::string TransferPreset::Describe() const
{
    std::string text;
    if (transferMode >= 0)
    {
        static const char * modes[] = { "binary", "ascii", "automatic" };
        text += std::string("transfer=") + modes[transferMode < 3 ? transferMode : 0];
    }
    if (preserveTime >= 0)
    {
        if (!text.empty()) text += " ";
        if (preserveTimeDirs > 0 && preserveTime > 0)
        {
            text += "preservetime=all";
        }
        else
        {
            text += std::string("preservetime=") + (preserveTime ? "on" : "off");
        }
    }
    if (newerOnly >= 0)
    {
        if (!text.empty()) text += " ";
        text += std::string("neweronly=") + (newerOnly ? "on" : "off");
    }
    if (speedLimit >= 0)
    {
        if (!text.empty()) text += " ";
        text += "speed=" + std::to_string(speedLimit);
    }
    if (resumeSupport >= 0)
    {
        if (!text.empty()) text += " ";
        if (resumeSupport == 1)
        {
            text += "resumesupport=" +
                std::to_string(resumeThreshold >= 0 ? resumeThreshold / 1024 : 0);
        }
        else
        {
            text += std::string("resumesupport=") + (resumeSupport == 0 ? "on" : "off");
        }
    }
    if (permissions == -1)
    {
        if (!text.empty()) text += " ";
        text += "permissions=off";
    }
    else if (permissions == -2)
    {
        if (!text.empty()) text += " ";
        text += "permissions=fromfile";
    }
    else if (permissions >= 0)
    {
        if (!text.empty()) text += " ";
        char octal[16];
        snprintf(octal, sizeof(octal), "%o", permissions);
        text += std::string("permissions=") + octal;
    }
    if (HasSessionRule())
    {
        if (!text.empty()) text += " ";
        text += "for";
        if (!host.empty()) text += " host=" + host;
        if (!userName.empty()) text += " user=" + userName;
        if (!remoteDirectory.empty()) text += " remotedir=" + remoteDirectory;
        if (!localDirectory.empty()) text += " localdir=" + localDirectory;
    }
    if (HasMaskRule())
    {
        if (!text.empty()) text += " ";
        text += "mask=" + mask;
    }
    if (text.empty())
    {
        text = "(no settings)";
    }
    return text;
}

TransferPresetStore::TransferPresetStore() : mPath(DefaultPath())
{
    std::string error;
    Load(error);
}

TransferPresetStore::TransferPresetStore(const std::string & path) : mPath(path)
{
    std::string error;
    Load(error);
}

std::string TransferPresetStore::DefaultPath()
{
    return ConfigDirectory() + "/transfer-presets.ini";
}

bool TransferPresetStore::Load(std::string & error)
{
    error.clear();
    mPresets.clear();
    std::ifstream file(mPath.c_str());
    if (!file.is_open())
    {
        /* No file is an empty store, not an error. */
        return true;
    }
    std::string line;
    TransferPreset current;
    bool inSection = false;
    while (std::getline(file, line))
    {
        const std::string trimmed = TrimCopy(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';')
        {
            continue;
        }
        if (trimmed[0] == '[')
        {
            if (inSection && !current.name.empty())
            {
                mPresets.push_back(current);
            }
            const size_t close = trimmed.find(']');
            if (close == std::string::npos)
            {
                error = "The preset file '" + mPath + "' has a section "
                    "header without a closing ']': " + trimmed;
                return false;
            }
            current = TransferPreset();
            current.name = TrimCopy(trimmed.substr(1, close - 1));
            if (current.name.empty())
            {
                error = "The preset file '" + mPath + "' has an unnamed section.";
                return false;
            }
            inSection = true;
            continue;
        }
        if (!inSection)
        {
            error = "The preset file '" + mPath + "' has a setting before "
                "any section: " + trimmed;
            return false;
        }
        const size_t equals = trimmed.find('=');
        if (equals == std::string::npos)
        {
            error = "The preset file '" + mPath + "' has a line that is not "
                "'key = value': " + trimmed;
            return false;
        }
        std::string settingError;
        if (!ParseSetting(TrimCopy(trimmed.substr(0, equals)),
            TrimQuotes(TrimCopy(trimmed.substr(equals + 1))), current, settingError))
        {
            error = "The preset '" + current.name + "' in '" + mPath +
                "': " + settingError;
            return false;
        }
    }
    if (inSection && !current.name.empty())
    {
        mPresets.push_back(current);
    }
    return true;
}

bool TransferPresetStore::Save(std::string & error) const
{
    error.clear();
    const size_t slash = mPath.rfind('/');
    if (slash != std::string::npos)
    {
        if (!CreatePrivateDirectory(mPath.substr(0, slash), error))
        {
            return false;
        }
    }
    std::string tempPattern = mPath + ".tmp.XXXXXX";
    std::vector<char> tempBuf(tempPattern.begin(), tempPattern.end());
    tempBuf.push_back('\0');
    const int fd = mkstemp(tempBuf.data());
    if (fd < 0)
    {
        error = "The preset file '" + mPath + "' cannot be written.";
        return false;
    }
    (void)fchmod(fd, 0600);
    const std::string tempPath(tempBuf.data());
    close(fd);
    std::ofstream file(tempPath.c_str(), std::ios::trunc);
    if (!file.is_open())
    {
        remove(tempPath.c_str());
        error = "The preset file '" + mPath + "' cannot be written.";
        return false;
    }
    file << "# Named transfer settings and the rules that apply them;\n"
         << "# see 'help savepreset'. Sections are the preset names.\n";
    for (size_t i = 0; i < mPresets.size(); i++)
    {
        const TransferPreset & p = mPresets[i];
        file << "\n[" << p.name << "]\n";
        if (p.transferMode >= 0)
        {
            static const char * modes[] = { "binary", "ascii", "automatic" };
            file << "transfer = " << modes[p.transferMode < 3 ? p.transferMode : 0] << "\n";
        }
        if (p.preserveTime >= 0)
        {
            file << "preservetime = "
                 << (p.preserveTimeDirs > 0 && p.preserveTime > 0 ? "all" :
                     p.preserveTime ? "on" : "off")
                 << "\n";
        }
        if (p.newerOnly >= 0)
        {
            file << "neweronly = " << (p.newerOnly ? "on" : "off") << "\n";
        }
        if (p.speedLimit >= 0)
        {
            file << "speed = " << p.speedLimit << "\n";
        }
        if (p.resumeSupport >= 0)
        {
            if (p.resumeSupport == 1)
            {
                file << "resumesupport = " << (p.resumeThreshold >= 0 ?
                    p.resumeThreshold / 1024 : 0) << "\n";
            }
            else
            {
                file << "resumesupport = " << (p.resumeSupport == 0 ? "on" : "off") << "\n";
            }
        }
        if (p.permissions == -1)
        {
            file << "permissions = off\n";
        }
        else if (p.permissions == -2)
        {
            file << "permissions = fromfile\n";
        }
        else if (p.permissions >= 0)
        {
            file << "permissions = " << std::oct << p.permissions << std::dec << "\n";
        }
        if (!p.host.empty()) file << "host = " << p.host << "\n";
        if (!p.userName.empty()) file << "user = " << p.userName << "\n";
        if (!p.remoteDirectory.empty()) file << "remotedir = " << p.remoteDirectory << "\n";
        if (!p.localDirectory.empty()) file << "localdir = " << p.localDirectory << "\n";
        if (!p.mask.empty()) file << "mask = " << p.mask << "\n";
    }
    file.flush();
    if (!file.good())
    {
        file.close();
        remove(tempPath.c_str());
        error = "Writing the preset file '" + mPath + "' failed.";
        return false;
    }
    file.close();
    if (rename(tempPath.c_str(), mPath.c_str()) != 0)
    {
        remove(tempPath.c_str());
        error = "Writing the preset file '" + mPath + "' failed.";
        return false;
    }
    (void)chmod(mPath.c_str(), 0600);
    return true;
}

const TransferPreset * TransferPresetStore::Find(const std::string & name) const
{
    for (size_t i = 0; i < mPresets.size(); i++)
    {
        if (mPresets[i].name == name)
        {
            return &mPresets[i];
        }
    }
    for (size_t i = 0; i < mPresets.size(); i++)
    {
        if (LowerCopy(mPresets[i].name) == LowerCopy(name))
        {
            return &mPresets[i];
        }
    }
    return NULL;
}

bool TransferPresetStore::AddOrUpdate(const TransferPreset & preset,
    std::string & error)
{
    error.clear();
    if (!IsValidName(preset.name))
    {
        error = "'" + preset.name + "' is not a usable preset name.";
        return false;
    }
    for (size_t i = 0; i < mPresets.size(); i++)
    {
        if (LowerCopy(mPresets[i].name) == LowerCopy(preset.name))
        {
            mPresets[i] = preset;
            return true;
        }
    }
    mPresets.push_back(preset);
    return true;
}

bool TransferPresetStore::Remove(const std::string & name, std::string & error)
{
    error.clear();
    for (size_t i = 0; i < mPresets.size(); i++)
    {
        if (LowerCopy(mPresets[i].name) == LowerCopy(name))
        {
            mPresets.erase(mPresets.begin() + i);
            return true;
        }
    }
    error = "There is no transfer preset named '" + name + "'.";
    return false;
}

const TransferPreset * TransferPresetStore::MatchSession(const std::string & host,
    const std::string & user, const std::string & remoteDirectory,
    const std::string & localDirectory) const
{
    for (size_t i = 0; i < mPresets.size(); i++)
    {
        const TransferPreset & p = mPresets[i];
        if (!p.HasSessionRule())
        {
            continue;
        }
        if (!HostRuleMatches(p.host, host) ||
            !FieldMatches(p.userName, user) ||
            !FieldMatches(p.remoteDirectory, remoteDirectory) ||
            !FieldMatches(p.localDirectory, localDirectory))
        {
            continue;
        }
        return &p;
    }
    return NULL;
}

const TransferPreset * TransferPresetStore::MatchMask(const std::string & fileName) const
{
    for (size_t i = 0; i < mPresets.size(); i++)
    {
        const TransferPreset & p = mPresets[i];
        if (!p.HasMaskRule())
        {
            continue;
        }
        if (PresetFileMaskMatches(p.mask, fileName))
        {
            return &p;
        }
    }
    return NULL;
}

bool TransferPresetStore::ParseSetting(const std::string & rawKey,
    const std::string & value, TransferPreset & preset, std::string & error)
{
    const std::string key = LowerCopy(TrimCopy(rawKey));
    error.clear();
    if (key == "transfer")
    {
        TransferMode mode;
        if (!ParseTransferMode(LowerCopy(value), mode))
        {
            error = "the value of 'transfer' must be binary, ascii or automatic.";
            return false;
        }
        preset.transferMode = static_cast<int>(mode);
        return true;
    }
    if (key == "preservetime")
    {
        const std::string v = LowerCopy(value);
        if (v == "all")
        {
            preset.preserveTime = 1;
            preset.preserveTimeDirs = 1;
            return true;
        }
        bool on = false;
        if (!ParseOnOff(v, on))
        {
            error = "the value of 'preservetime' must be on, off or all.";
            return false;
        }
        preset.preserveTime = on ? 1 : 0;
        if (!on)
        {
            preset.preserveTimeDirs = 0;
        }
        return true;
    }
    if (key == "neweronly")
    {
        bool on = false;
        if (!ParseOnOff(value, on))
        {
            error = "the value of 'neweronly' must be on or off.";
            return false;
        }
        preset.newerOnly = on ? 1 : 0;
        return true;
    }
    if (key == "speed")
    {
        long long kib = 0;
        if (!ParseLong(value, kib) || kib < 0 ||
            kib > static_cast<long long>(UINT_MAX))
        {
            error = "the value of 'speed' must be a whole number of kibibytes "
                "per second (0 removes the limit).";
            return false;
        }
        preset.speedLimit = kib;
        return true;
    }
    if (key == "resumesupport")
    {
        const std::string v = LowerCopy(value);
        if (v == "on")
        {
            preset.resumeSupport = 0;
            return true;
        }
        if (v == "off")
        {
            preset.resumeSupport = 2;
            return true;
        }
        long long kib = 0;
        if (!ParseLong(v, kib) || kib < 0 || kib > LLONG_MAX / 1024LL)
        {
            error = "the value of 'resumesupport' must be on, off or a number "
                "of kibibytes a file must reach to be resumed.";
            return false;
        }
        preset.resumeSupport = 1;
        preset.resumeThreshold = kib * 1024;
        return true;
    }
    if (key == "permissions")
    {
        const std::string v = LowerCopy(value);
        if (v == "off")
        {
            preset.permissions = -1;
            return true;
        }
        if (v == "fromfile")
        {
            preset.permissions = -2;
            return true;
        }
        if (v.empty() || v.size() > 6)
        {
            error = "the value of 'permissions' must be an octal number from "
                "0 through 7777, 'off' or 'fromfile'.";
            return false;
        }
        unsigned long octal = 0;
        for (size_t i = 0; i < v.size(); i++)
        {
            if (v[i] < '0' || v[i] > '7')
            {
                error = "the value of 'permissions' must be an octal number "
                    "from 0 through 7777, 'off' or 'fromfile'.";
                return false;
            }
            octal = octal * 8 + static_cast<unsigned long>(v[i] - '0');
        }
        if (octal > 07777UL)
        {
            error = "the value of 'permissions' must be an octal number from "
                "0 through 7777, 'off' or 'fromfile'.";
            return false;
        }
        preset.permissions = static_cast<int>(octal);
        return true;
    }
    if (key == "host" || key == "hostname")
    {
        preset.host = TrimCopy(value);
        return true;
    }
    if (key == "user" || key == "username")
    {
        preset.userName = TrimCopy(value);
        return true;
    }
    if (key == "remotedir" || key == "remote_directory")
    {
        preset.remoteDirectory = TrimCopy(value);
        return true;
    }
    if (key == "localdir" || key == "local_directory")
    {
        preset.localDirectory = TrimCopy(value);
        return true;
    }
    if (key == "mask" || key == "filemask")
    {
        preset.mask = TrimCopy(value);
        if (preset.mask.empty())
        {
            error = "'mask' needs a wildcard such as *.txt.";
            return false;
        }
        return true;
    }
    error = "'" + rawKey + "' is not a transfer preset setting; supported "
        "are transfer, preservetime, neweronly, speed, resumesupport, "
        "permissions, host, user, remotedir, localdir and mask.";
    return false;
}

bool TransferPresetStore::IsValidName(const std::string & name)
{
    if (name.empty())
    {
        return false;
    }
    if (name[0] == ' ' || name[0] == '\t' ||
        name[name.size() - 1] == ' ' || name[name.size() - 1] == '\t')
    {
        return false;
    }
    if (name[0] == '[' || name.find_first_of("\r\n[]") != std::string::npos)
    {
        return false;
    }
    for (size_t i = 0; i < name.size(); i++)
    {
        if (static_cast<unsigned char>(name[i]) < 0x20)
        {
            return false;
        }
    }
    return true;
}

} // namespace linscp
