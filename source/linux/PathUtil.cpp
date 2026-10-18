#include "PathUtil.h"

#include "ListingParse.h"
#include "Platform.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace linscp {

namespace {

bool IsLocalSeparator(char c)
{
    return c == '/';
}

} // namespace

std::vector<std::string> SplitCommandLine(const std::string & line)
{
    std::vector<std::string> result;
    std::string word;
    bool haveWord = false;
    size_t i = 0;
    while (i < line.size())
    {
        char c = line[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        {
            if (haveWord)
            {
                result.push_back(word);
                word.clear();
                haveWord = false;
            }
            i++;
        }
        else if (c == '\'' || c == '"')
        {
            char quote = c;
            haveWord = true;
            i++;
            while (i < line.size() && line[i] != quote)
            {
                /*
                 * Inside double quotes a backslash is an escape only in
                 * front of a double quote or of another backslash, as a
                 * POSIX shell does it. It used to escape any character,
                 * which is the rule a Windows command line follows and
                 * the rule this client inherited with it. On Linux a
                 * backslash is an ordinary character of a file name, so
                 * the old rule silently shortened it: a path written
                 * "C:\Users\me" arrived as "C:Usersme", and a file named
                 * "a\b.txt" was read as "ab.txt" - the name of one file
                 * became the name of another. A script carried over
                 * from the Windows client must keep its backslashes.
                 */
                if (quote == '"' && line[i] == '\\' && i + 1 < line.size() &&
                    (line[i + 1] == '"' || line[i + 1] == '\\'))
                {
                    i++;
                }
                word += line[i];
                i++;
            }
            if (i < line.size())
            {
                i++; // skip the closing quote
            }
        }
        else if (c == '\\' && i + 1 < line.size())
        {
            haveWord = true;
            i++;
            word += line[i];
            i++;
        }
        else
        {
            haveWord = true;
            word += c;
            i++;
        }
    }
    if (haveWord)
    {
        result.push_back(word);
    }
    return result;
}

std::vector<std::string> SplitCommands(const std::string & text)
{
    std::vector<std::string> result;
    std::string current;
    char quote = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        char c = text[i];
        if (quote != 0)
        {
            if (c == '\\' && quote == '"' && i + 1 < text.size())
            {
                current += c;
                i++;
                current += text[i];
                continue;
            }
            if (c == quote)
            {
                quote = 0;
            }
            current += c;
        }
        else if (c == '\'' || c == '"')
        {
            quote = c;
            current += c;
        }
        else if (c == '\\' && i + 1 < text.size())
        {
            current += c;
            i++;
            current += text[i];
        }
        else if (c == ';')
        {
            result.push_back(current);
            current.clear();
        }
        else
        {
            current += c;
        }
    }
    if (!current.empty())
    {
        result.push_back(current);
    }
    return result;
}

bool IsRemoteAbsolutePath(const std::string & path)
{
    return !path.empty() && path[0] == '/';
}

std::string RemoteDirName(const std::string & path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos)
    {
        return std::string();
    }
    if (pos == 0)
    {
        return std::string("/");
    }
    return path.substr(0, pos);
}

std::string RemoteFileName(const std::string & path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos)
    {
        return path;
    }
    return path.substr(pos + 1);
}

std::string JoinRemotePath(const std::string & dir, const std::string & name)
{
    if (name.empty())
    {
        return dir;
    }
    if (IsRemoteAbsolutePath(name))
    {
        return name;
    }
    if (dir.empty())
    {
        return name;
    }
    if (dir[dir.size() - 1] == '/')
    {
        return dir + name;
    }
    return dir + "/" + name;
}

/* Resolves a possibly relative path against cwd, collapsing '.' and '..'.
 * A trailing slash of the input is not preserved unless the result is
 * the root directory. */
std::string ResolveRemotePath(const std::string & cwd, const std::string & path)
{
    std::string full;
    std::vector<std::string> parts;
    if (IsRemoteAbsolutePath(path))
    {
        full = path;
    }
    else
    {
        full = JoinRemotePath(cwd.empty() ? std::string("/") : cwd, path);
    }

    size_t i = 0;
    while (i < full.size())
    {
        if (full[i] == '/')
        {
            i++;
            continue;
        }
        size_t end = full.find('/', i);
        if (end == std::string::npos)
        {
            end = full.size();
        }
        std::string part = full.substr(i, end - i);
        if (part == "..")
        {
            if (!parts.empty())
            {
                parts.pop_back();
            }
        }
        else if (part != "." && !part.empty())
        {
            parts.push_back(part);
        }
        i = end;
    }

    std::string result;
    for (size_t n = 0; n < parts.size(); n++)
    {
        result += "/" + parts[n];
    }
    if (result.empty())
    {
        result = "/";
    }
    return result;
}

std::string ExpandTilde(const std::string & path)
{
    if (path.empty() || path[0] != '~')
    {
        return path;
    }
    std::string home = HomeDirectory();
    if (home.empty())
    {
        return path;
    }
    if (path.size() == 1)
    {
        return home;
    }
    if (path[1] != '/')
    {
        return path; // '~user' is not supported
    }
    return JoinLocalPath(home, path.substr(2));
}

bool IsLocalAbsolutePath(const std::string & path)
{
    return !path.empty() && path[0] == '/';
}

std::string LocalDirName(const std::string & path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos)
    {
        return std::string(".");
    }
    if (pos == 0)
    {
        return std::string("/");
    }
    return path.substr(0, pos);
}

std::string LocalFileName(const std::string & path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos)
    {
        return path;
    }
    return path.substr(pos + 1);
}

std::string JoinLocalPath(const std::string & dir, const std::string & name)
{
    if (name.empty())
    {
        return dir;
    }
    if (name[0] == '/')
    {
        return name;
    }
    if (dir.empty())
    {
        return name;
    }
    if (IsLocalSeparator(dir[dir.size() - 1]))
    {
        return dir + name;
    }
    return dir + '/' + name;
}

std::string ResolveLocalPath(const std::string & cwd, const std::string & path)
{
    std::string expanded = ExpandTilde(path);
    if (!expanded.empty() && expanded[0] == '/')
    {
        return expanded;
    }
    if (expanded == ".")
    {
        return cwd;
    }
    std::string joined = JoinLocalPath(cwd, expanded);
    // Collapse './' and '../' the same way as for remote paths; the local
    // tree of a LinSCP transfer is always POSIX on this platform.
    return ResolveRemotePath(cwd, joined);
}

bool HasWildcard(const std::string & path)
{
    return path.find('*') != std::string::npos ||
        path.find('?') != std::string::npos;
}

bool MatchesMask(const std::string & mask, const std::string & name)
{
    /* Greedy wildcard matching with backtracking to the most recent '*'.
     * This avoids recursive stack growth on long names and masks, while
     * using only constant auxiliary memory. Matching is case sensitive:
     * the local file systems this client runs on distinguish case. */
    size_t maskIndex = 0;
    size_t nameIndex = 0;
    size_t lastStar = std::string::npos;
    size_t retryNameIndex = 0;

    while (nameIndex < name.size())
    {
        if (maskIndex < mask.size() &&
            (mask[maskIndex] == '?' || mask[maskIndex] == name[nameIndex]))
        {
            maskIndex++;
            nameIndex++;
        }
        else if (maskIndex < mask.size() && mask[maskIndex] == '*')
        {
            lastStar = maskIndex++;
            retryNameIndex = nameIndex;
        }
        else if (lastStar != std::string::npos)
        {
            maskIndex = lastStar + 1;
            nameIndex = ++retryNameIndex;
        }
        else
        {
            return false;
        }
    }

    while (maskIndex < mask.size() && mask[maskIndex] == '*')
    {
        maskIndex++;
    }
    return maskIndex == mask.size();
}

std::string FormatSize(uint64_t size)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%llu",
        static_cast<unsigned long long>(size));
    return std::string(buffer);
}

std::string FormatPermissions(unsigned long permissions)
{
    /* One implementation, not two: this used to spell out its own mode
     * string and knew only the directory type, so 'ls' and 'attr' printed
     * a symbolic link, a device or a socket as an ordinary file while the
     * shared listing parser printed the type the attributes really
     * carried. PermissionsString() is what a listing line is built from. */
    return PermissionsString(permissions);
}

std::string FormatFileTime(unsigned long time)
{
    /* The month name and day padding are formatted explicitly so listing
     * output is locale-independent. */
    static const char * months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    time_t t = static_cast<time_t>(time);
    struct tm tmResult;
    if (!LocalTime(t, tmResult))
    {
        return "unknown";
    }
    char buffer[32];
    time_t now = ::time(NULL);
    // Within six months show the time, otherwise the year, like 'ls -l'.
    if (t > now - 180 * 24 * 60 * 60 && t < now + 180 * 24 * 60 * 60)
    {
        snprintf(buffer, sizeof(buffer), "%s %2d %02d:%02d",
            months[tmResult.tm_mon % 12], tmResult.tm_mday,
            tmResult.tm_hour, tmResult.tm_min);
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "%s %2d  %d",
            months[tmResult.tm_mon % 12], tmResult.tm_mday,
            tmResult.tm_year + 1900);
    }
    return std::string(buffer);
}

/* The date and clock split of FormatFileTime for the 'lls' columns. */
std::string FormatFileDate(unsigned long time)
{
    static const char * months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    time_t t = static_cast<time_t>(time);
    struct tm tmResult;
    if (!LocalTime(t, tmResult))
    {
        return "unknown";
    }
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s %2d %d",
        months[tmResult.tm_mon % 12], tmResult.tm_mday,
        tmResult.tm_year + 1900);
    return std::string(buffer);
}

std::string FormatFileClock(unsigned long time)
{
    time_t t = static_cast<time_t>(time);
    struct tm tmResult;
    if (!LocalTime(t, tmResult))
    {
        return "??";
    }
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%02d:%02d",
        tmResult.tm_hour, tmResult.tm_min);
    return std::string(buffer);
}

} // namespace linscp

/* Permission parsing, shared by 'chmod' and by '-permissions='. */
namespace linscp {

/*
 * A symbolic permission expression, in the style of chmod(1): a comma
 * separated list of '<who>(<op><perms>)+' clauses, where <who> is any of
 * u, g, o, a (default 'a' for '=', and required for '+' and '-'), <op> is
 * one of '+', '-' or '=' and <perms> is any of r, w, x, X (exec only for
 * directories and for files that are already executable), s, t and the
 * letters u, g and o, which copy the corresponding class of the mode that
 * the file has now. Several operator groups in one clause apply left to
 * right, as chmod(1) applies them: 'u+x-w' is 'u+x' and then 'u-w'.
 *
 * 'u=rw' leaves the group and the other bits alone. The process umask is
 * deliberately not applied to '=': the caller states the mode it wants.
 */
bool ParseSymbolicPermissions(const std::string & text, unsigned long current,
    bool isDirectory, unsigned long & result, std::string & error)
{
    /* The caller's mode is only ever replaced by a finished one: a
     * clause that is refused half way through left the part it had
     * already applied behind, so a failure answered with a mode nobody
     * asked for. */
    result = current;
    error.clear();
    unsigned long mode = current;

    std::string wanted;
    TrimString(text, wanted);
    if (wanted.empty())
    {
        error = "the permission mode is empty";
        return false;
    }

    size_t i = 0;
    size_t clauses = 0;
    while (i < wanted.size())
    {
        while (i < wanted.size() &&
               (wanted[i] == ',' || isspace(static_cast<unsigned char>(wanted[i]))))
        {
            i++;
        }
        if (i >= wanted.size())
        {
            break;
        }
        clauses++;

        /* 1 = owner, 2 = group, 4 = other */
        unsigned int who = 0;
        while (i < wanted.size())
        {
            const char c = static_cast<char>(tolower(static_cast<unsigned char>(wanted[i])));
            if (c == 'u') { who |= 1; }
            else if (c == 'g') { who |= 2; }
            else if (c == 'o') { who |= 4; }
            else if (c == 'a') { who |= 7; }
            else
            {
                break;
            }
            i++;
        }

        /*
         * One clause is '<who>' followed by one or more '<op><letters>'
         * groups, which is what chmod(1) reads: 'u+x-w' gives the owner
         * the execute bit and then takes the write bit away again. Only
         * the first group was read before, so the rest of the clause was
         * refused as an unknown permission letter - and the graphical
         * client, which applies the same expression to a local file with
         * chmod(1)'s own grammar, accepted a mode the remote chmod then
         * refused.
         */
        size_t groups = 0;
        while (i < wanted.size() &&
               (wanted[i] == '+' || wanted[i] == '-' || wanted[i] == '='))
        {
            const char op = wanted[i++];
            if (who == 0)
            {
                if (op != '=')
                {
                    /* '+x' named nobody and changed nothing at all. A
                     * mode that silently does nothing is worse than one
                     * that is refused, and the graphical client already
                     * asks for u, g, o or a in front of it. */
                    error = "'+' and '-' need u, g, o or a in front of "
                        "them in '" + text + "'";
                    return false;
                }
                /* '=rwx' names nobody in front of it, so it is for
                 * everybody, and the groups behind it are for the same
                 * classes. */
                who = 7;
            }
            groups++;

            std::string perms;
            while (i < wanted.size() && wanted[i] != ',' &&
                   wanted[i] != '+' && wanted[i] != '-' && wanted[i] != '=' &&
                   !isspace(static_cast<unsigned char>(wanted[i])))
            {
                /* The case matters here: 'X' means something else than
                 * 'x'. */
                perms += wanted[i];
                i++;
            }
            if (perms.empty())
            {
                error = "expected a permission letter in '" + text + "'";
                return false;
            }
            for (size_t p = 0; p < perms.size(); p++)
            {
                /* chmod(1) accepts these and only these; case matters. */
                const char c = perms[p];
                if (strchr("rwxXstuugo", c) == NULL)
                {
                    error = "unknown permission letter '" +
                        std::string(1, c) + "' in '" + text + "'";
                    return false;
                }
            }
            /* The bits are the remote file's own; they are written out as
             * numbers because the value travels over SFTP regardless of what
             * the local C library names them. */
            const bool anyExec = (current & 0111) != 0;

            for (unsigned int slot = 0; slot < 3; slot++)
            {
                if ((who & (1u << slot)) == 0)
                {
                    continue;
                }
                const int shift = static_cast<int>(2 - slot) * 3;
                const unsigned long slotMask = static_cast<unsigned long>(0x7 << shift);

                unsigned long add = 0;
                for (size_t p = 0; p < perms.size(); p++)
                {
                    switch (perms[p])
                    {
                    case 'r': add |= static_cast<unsigned long>(0x4 << shift); break;
                    case 'w': add |= static_cast<unsigned long>(0x2 << shift); break;
                    case 'x': add |= static_cast<unsigned long>(0x1 << shift); break;
                    case 'X':
                        if (anyExec || isDirectory)
                        {
                            add |= static_cast<unsigned long>(0x1 << shift);
                        }
                        break;
                    case 'u':
                        add |= static_cast<unsigned long>(((current & 0700) >> 6) << shift);
                        break;
                    case 'g':
                        add |= static_cast<unsigned long>(((current & 0070) >> 3) << shift);
                        break;
                    case 'o':
                        add |= static_cast<unsigned long>((current & 0007) << shift);
                        break;
                    default:
                        break;
                    }
                }

                if (op == '+')
                {
                    mode = static_cast<unsigned long>(mode | add);
                }
                else if (op == '-')
                {
                    mode = static_cast<unsigned long>(mode & ~add);
                }
                else
                {
                    mode = static_cast<unsigned long>((mode & ~slotMask) | (add & slotMask));
                }

                /* The special bits live outside the three permission classes. */
                if (perms.find('s') != std::string::npos)
                {
                    const unsigned long special = (slot == 0 ? 04000 :
                        (slot == 1 ? 02000 : 0));
                    mode = (op == '-' ? static_cast<unsigned long>(mode & ~special)
                                        : static_cast<unsigned long>(mode | special));
                }
                if (perms.find('t') != std::string::npos &&
                    (who & (1u << slot)) != 0 && slot == 2)
                {
                    mode = (op == '-' ? static_cast<unsigned long>(mode & ~01000)
                                        : static_cast<unsigned long>(mode | 01000));
                }
            }
        }
        if (groups == 0)
        {
            error = "expected '+', '-' or '=' in '" + text + "'";
            return false;
        }
    }
    if (clauses == 0)
    {
        error = "'" + text + "' states no permission at all";
        return false;
    }
    result = mode;
    return true;
}

bool TrimString(const std::string & text, std::string & result)
{
    size_t first = 0;
    while (first < text.size() && isspace(static_cast<unsigned char>(text[first])))
    {
        first++;
    }
    size_t last = text.size();
    while (last > first && isspace(static_cast<unsigned char>(text[last - 1])))
    {
        last--;
    }
    result = text.substr(first, last - first);
    return !result.empty();
}

/* A WinSCP-style octal permission value: '600', '0600', '00600'. */
bool ParseOctalMode(const std::string & text, unsigned long & result)
{
    std::string digits = text;
    if (digits.size() > 1 && (digits[0] == '0' || digits[0] == 'o'))
    {
        digits = digits.substr(1);
    }
    if (digits.empty() || digits.size() > 4)
    {
        return false;
    }
    unsigned long mode = 0;
    for (size_t i = 0; i < digits.size(); i++)
    {
        if (digits[i] < '0' || digits[i] > '7')
        {
            return false;
        }
        mode = static_cast<unsigned long>(mode * 8 + (digits[i] - '0'));
    }
    result = mode;
    return true;
}

/* An octal mode or a symbolic expression, as accepted by 'chmod'. */
bool ParsePermissions(const std::string & text, unsigned long current, bool isDirectory,
    unsigned long & result, std::string & error)
{
    if (!text.empty() && isdigit(static_cast<unsigned char>(text[0])))
    {
        if (ParseOctalMode(text, result))
        {
            return true;
        }
        error = "'" + text + "' is not a valid octal mode";
        return false;
    }
    return ParseSymbolicPermissions(text, current, isDirectory, result, error);
}

} // namespace linscp
