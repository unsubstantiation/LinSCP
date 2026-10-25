/*
 * SyncPlanner: the comparison and planning engine of 'synchronize' and
 * 'keepuptodate'.
 *
 * The planner reads both trees through SyncFileSystem and returns a
 * plan; see SyncPlanner.h for the rules. Nothing here transfers,
 * creates or removes anything, which is what allows 'synchronize
 * -preview' to be completely safe and 'synchronize both -delete' to be
 * driven by the recorded state instead of by a guess.
 */

#include "SyncPlanner.h"

#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>

#include <algorithm>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

#include "LocalFs.h"
#include "PathUtil.h"
#include "Platform.h"

namespace linscp {

namespace {

unsigned long long NowSeconds()
{
    return static_cast<unsigned long long>(time(NULL));
}

} // namespace

const char * SyncModeName(SyncMode mode)
{
    switch (mode)
    {
        case SyncMode::Local:  return "local";
        case SyncMode::Remote: return "remote";
        case SyncMode::Both:   return "both";
    }
    return "local";
}

std::string SyncCriteriaName(const SyncCriteria & criteria)
{
    if (criteria.Empty())
    {
        return "none";
    }
    /* The single word upstream and this console use for the pair. */
    if (criteria.time && criteria.size && !criteria.checksum)
    {
        return "either";
    }
    std::string name;
    if (criteria.time)
    {
        name = "time";
    }
    if (criteria.size)
    {
        name += name.empty() ? std::string("size") : std::string(",size");
    }
    if (criteria.checksum)
    {
        name += name.empty() ? std::string("checksum") :
            std::string(",checksum");
    }
    return name;
}

namespace {

/* True when 'word' is 'name', whatever the case of 'word'. */
bool SameWord(const std::string & word, const char * name)
{
    if (word.size() != strlen(name))
    {
        return false;
    }
    for (size_t i = 0; i < word.size(); i++)
    {
        if (tolower(static_cast<unsigned char>(word[i])) != name[i])
        {
            return false;
        }
    }
    return true;
}

/* The words '-criteria=' takes. 'both' is upstream's synonym of 'either',
 * and 'none' switches every comparison off. */
struct CriteriaWord
{
    const char * name;
    bool time;
    bool size;
    bool checksum;
    /* True for the words that name a whole set of criteria: they stand on
     * their own, so a list cannot add to them. */
    bool whole;
};

const CriteriaWord kCriteriaWords[] =
{
    { "none",     false, false, false, true  },
    { "either",   true,  true,  false, true  },
    { "both",     true,  true,  false, true  },
    { "time",     true,  false, false, false },
    { "size",     false, true,  false, false },
    { "checksum", false, false, true,  false },
};

const size_t kCriteriaWordCount = sizeof(kCriteriaWords) /
    sizeof(kCriteriaWords[0]);

} // namespace

bool ParseSyncCriteria(const std::string & text, SyncCriteria & criteria,
    std::string & error)
{
    std::string trimmed;
    if (!TrimString(text, trimmed))
    {
        /* '-criteria=' on its own has no value to parse. */
        error = "'-criteria=' needs a value: none, either, both, or a "
            "comma-separated list of time, size and checksum.";
        return false;
    }

    SyncCriteria result;
    result.time = false;
    result.size = false;
    result.checksum = false;

    size_t start = 0;
    bool seen = false;
    std::string whole;
    for (size_t i = 0; i <= text.size(); i++)
    {
        if (i < text.size() && text[i] != ',')
        {
            continue;
        }
        std::string item;
        TrimString(text.substr(start, i - start), item);
        start = i + 1;
        if (!whole.empty())
        {
            error = "'" + whole + "' already names the whole set of "
                "criteria, so " + (item.empty() ?
                    std::string("nothing may follow it in the list.") :
                    "'" + item + "' cannot follow it in the list.");
            return false;
        }
        if (item.empty())
        {
            /* 'time,' and 'time,,size' have an empty item where a name
             * belongs; refusing them keeps the list honest. */
            error = "The criteria list has an empty item; it takes 'time', "
                "'size' and 'checksum' separated by commas.";
            return false;
        }
        bool known = false;
        for (size_t w = 0; w < kCriteriaWordCount; w++)
        {
            if (!SameWord(item, kCriteriaWords[w].name))
            {
                continue;
            }
            known = true;
            if (kCriteriaWords[w].whole)
            {
                if (seen)
                {
                    error = "'" + item + "' already names the whole set of "
                        "criteria, so it cannot follow another item of the "
                        "list.";
                    return false;
                }
                whole = item;
                result.time = kCriteriaWords[w].time;
                result.size = kCriteriaWords[w].size;
                result.checksum = kCriteriaWords[w].checksum;
            }
            else
            {
                result.time = result.time || kCriteriaWords[w].time;
                result.size = result.size || kCriteriaWords[w].size;
                result.checksum = result.checksum || kCriteriaWords[w].checksum;
            }
            seen = true;
            break;
        }
        if (!known)
        {
            error = "Unsupported criteria '" + item + "' (use none, either, "
                "both, time, size or checksum, or a comma-separated list of "
                "time, size and checksum).";
            return false;
        }
    }
    criteria = result;
    return true;
}

const char * SyncActionName(SyncAction action)
{
    switch (action)
    {
        case SyncAction::None:         return "unchanged";
        case SyncAction::Download:     return "download";
        case SyncAction::Upload:       return "upload";
        case SyncAction::DeleteLocal:  return "delete-local";
        case SyncAction::DeleteRemote: return "delete-remote";
        case SyncAction::Conflict:     return "conflict";
    }
    return "unchanged";
}

bool ParseSyncConflictPolicy(const std::string & text,
    SyncConflictPolicy & policy, std::string & error)
{
    error.clear();
    std::string lower = text;
    for (size_t i = 0; i < lower.size(); i++)
    {
        lower[i] = static_cast<char>(tolower(static_cast<unsigned char>(lower[i])));
    }
    if (lower == "skip" || lower == "abort" || lower == "prompt")
    {
        policy = SyncConflictPolicy::Skip;
        return true;
    }
    if (lower == "local" || lower == "upload")
    {
        policy = SyncConflictPolicy::Local;
        return true;
    }
    if (lower == "remote" || lower == "download")
    {
        policy = SyncConflictPolicy::Remote;
        return true;
    }
    if (lower == "newer")
    {
        policy = SyncConflictPolicy::Newer;
        return true;
    }
    error = "Unsupported conflict policy '" + text +
        "' (use skip, local, remote or newer).";
    return false;
}

const char * SyncConflictPolicyName(SyncConflictPolicy policy)
{
    switch (policy)
    {
        case SyncConflictPolicy::Skip:   return "skip";
        case SyncConflictPolicy::Local:  return "local";
        case SyncConflictPolicy::Remote: return "remote";
        case SyncConflictPolicy::Newer:  return "newer";
    }
    return "skip";
}

/* ------------------------------------------------------------------ *
 * FileMask                                                            *
 * ------------------------------------------------------------------ */

namespace {

/* Matches one pattern component against one path component. */
bool MatchesComponent(const std::string & pattern, const std::string & text)
{
    return MatchesMask(pattern, text);
}

/* A directory mask matches the directory itself and any trailing part
 * of its path, so 'build/' and 'any/build/' both prune a directory named
 * 'build' at any depth. */
bool MatchesDirectoryPath(const FileMaskToken & token,
    const std::string & relativePath, const std::string & name)
{
    if (token.pattern.empty())
    {
        return true;
    }
    std::vector<std::string> patternParts;
    std::vector<std::string> pathParts;
    std::string part;
    const std::string & source = token.pattern;
    for (size_t i = 0; i <= source.size(); i++)
    {
        if (i < source.size() && source[i] != '/')
        {
            part += source[i];
            continue;
        }
        if (!part.empty())
        {
            patternParts.push_back(part);
        }
        part.clear();
    }
    /* At the root (or from the name-only overload) the entry has no
     * path below the root yet; its name is the whole path. */
    const std::string & path = relativePath.empty() ? name : relativePath;
    for (size_t i = 0; i <= path.size(); i++)
    {
        if (i < path.size() && path[i] != '/')
        {
            part += path[i];
            continue;
        }
        if (!part.empty())
        {
            pathParts.push_back(part);
        }
        part.clear();
    }
    /* A leading '*' component ('x/build/') stands for any prefix,
     * including none at all. */
    while (patternParts.size() > 1 && patternParts[0] == "*")
    {
        patternParts.erase(patternParts.begin());
    }
    if (patternParts.size() > pathParts.size())
    {
        return false;
    }
    const size_t offset = pathParts.size() - patternParts.size();
    for (size_t i = 0; i < patternParts.size(); i++)
    {
        if (!MatchesComponent(patternParts[i], pathParts[offset + i]))
        {
            return false;
        }
    }
    return true;
}

/* A file path mask matches the whole path below the transfer root. */
bool MatchesFilePath(const FileMaskToken & token, const std::string & relativePath)
{
    if (relativePath.empty())
    {
        return false;
    }
    return MatchesComponent(token.pattern, relativePath);
}

bool MatchesCriterion(unsigned long long value, unsigned long long threshold,
    int op)
{
    switch (op)
    {
        case 0: return value == threshold;
        case 1: return value < threshold;
        case 2: return value > threshold;
        case 3: return value <= threshold;
        case 4: return value >= threshold;
    }
    return false;
}

/* Size/time criteria apply to files only; 0 (unknown) never matches a
 * criterion, so a mask with a criterion never selects an entry whose
 * metadata the source could not report. */
bool MatchesCriteria(const FileMaskToken & token, unsigned long long size,
    unsigned long mtime)
{
    for (size_t i = 0; i < token.criteria.size(); i++)
    {
        const MaskCriterion & criterion = token.criteria[i];
        if (criterion.isSize)
        {
            if (size == 0 || !MatchesCriterion(size, criterion.size, criterion.op))
            {
                return false;
            }
        }
        else
        {
            if (mtime == 0 || !MatchesCriterion(mtime, criterion.time, criterion.op))
            {
                return false;
            }
        }
    }
    return true;
}

/* One token against one entry. 'forExclude' tells name-only masks that
 * they are being tested for pruning: an exclusion may prune a directory
 * of that name, an inclusion never does (the files below it may still
 * match). */
bool MatchesToken(const FileMaskToken & token, const std::string & name,
    bool isDirectory, unsigned long long size, unsigned long mtime,
    const std::string & relativePath, bool forExclude)
{
    if (isDirectory)
    {
        if (!token.criteria.empty())
        {
            return false;
        }
        if (!token.directoryOnly && !token.isPath)
        {
            return forExclude && MatchesComponent(token.pattern, name);
        }
        return MatchesDirectoryPath(token, relativePath, name);
    }
    if (token.directoryOnly)
    {
        return false;
    }
    if (!token.criteria.empty() && !MatchesCriteria(token, size, mtime))
    {
        return false;
    }
    if (token.isPath)
    {
        return MatchesFilePath(token, relativePath);
    }
    return MatchesComponent(token.pattern, name);
}

/* Parses the value of one size/time criterion ('1M', '500K',
 * '2026-01-31', '2026-01-31T12:30'). */
bool ParseCriterionValue(const std::string & text, size_t begin, size_t end,
    MaskCriterion & criterion, std::string & error)
{
    if (begin >= end)
    {
        error = "A mask criterion is missing its value.";
        return false;
    }
    const std::string value = text.substr(begin, end - begin);

    /* A date (with an optional time) is a time criterion. */
    if (value.size() >= 10 && value[4] == '-' && value[7] == '-')
    {
        struct tm fields;
        memset(&fields, 0, sizeof(fields));
        bool ok = true;
        for (size_t i = 0; ok && i < 10; i++)
        {
            if (i == 4 || i == 7)
            {
                continue;
            }
            if (value[i] < '0' || value[i] > '9')
            {
                ok = false;
            }
        }
            if (ok)
            {
                fields.tm_year = atoi(value.substr(0, 4).c_str()) - 1900;
                fields.tm_mon = atoi(value.substr(5, 2).c_str()) - 1;
                fields.tm_mday = atoi(value.substr(8, 2).c_str());
                if (fields.tm_mon < 0 || fields.tm_mon > 11 ||
                    fields.tm_mday < 1 || fields.tm_mday > 31 ||
                    fields.tm_year + 1900 < 1970)
                {
                    error = "The date '" + value + "' in a file mask is not valid.";
                    return false;
                }
                if (value.size() > 10)
            {
                if (value[10] != 'T' || value.size() < 16)
                {
                    ok = false;
                }
                else
                {
                    for (size_t i = 11; ok && i < value.size(); i++)
                    {
                        if (i != 13 && (value[i] < '0' || value[i] > '9'))
                        {
                            ok = false;
                        }
                    }
                    if (ok)
                    {
                        fields.tm_hour = atoi(value.substr(11, 2).c_str());
                        fields.tm_min = atoi(value.substr(14, 2).c_str());
                        if (value.size() == 19 && value[16] == ':')
                        {
                            fields.tm_sec = atoi(value.substr(17, 2).c_str());
                        }
                        else if (value.size() != 16)
                        {
                            ok = false;
                        }
                        if (fields.tm_hour > 23 || fields.tm_min > 59 ||
                            fields.tm_sec > 59)
                        {
                            ok = false;
                        }
                    }
                }
            }
            if (ok)
            {
                fields.tm_isdst = -1;
                const time_t seconds = mktime(&fields);
                if (seconds == static_cast<time_t>(-1))
                {
                    error = "The date '" + value + "' in a file mask is not valid.";
                    return false;
                }
                criterion.isSize = false;
                criterion.time = static_cast<unsigned long>(seconds);
                return true;
            }
        }
        if (!ok)
        {
            error = "The date '" + value + "' in a file mask is not valid "
                "(use yyyy-mm-dd or yyyy-mm-ddThh:mm[:ss]).";
            return false;
        }
    }

    /* Everything else is a byte count with an optional K/M/G suffix. */
    size_t digits = 0;
    while (digits < value.size() &&
        value[digits] >= '0' && value[digits] <= '9')
    {
        digits++;
    }
    if (digits == 0)
    {
        error = "The value '" + value + "' of a file mask criterion is "
            "neither a size (with optional K, M or G) nor a date.";
        return false;
    }
    unsigned long long bytes = 0;
    for (size_t i = 0; i < digits; i++)
    {
        const unsigned long long digit =
            static_cast<unsigned long long>(value[i] - '0');
        if (bytes > (ULLONG_MAX - digit) / 10ULL)
        {
            error = "The size '" + value + "' in a file mask is too large.";
            return false;
        }
        bytes = bytes * 10ULL + digit;
    }
    std::string suffix = value.substr(digits);
    if (!suffix.empty())
    {
        const char unit = static_cast<char>(toupper(
            static_cast<unsigned char>(suffix[0])));
        if (suffix.size() != 1 ||
            (unit != 'K' && unit != 'M' && unit != 'G' && unit != 'T'))
        {
            error = "The size suffix '" + suffix + "' in a file mask is "
                "not supported (use K, M, G or T).";
            return false;
        }
        const unsigned long long shift = unit == 'K' ? 10ULL :
            unit == 'M' ? 20ULL : unit == 'G' ? 30ULL : 40ULL;
        if (bytes > (ULLONG_MAX >> shift))
        {
            error = "The size '" + value + "' in a file mask is too large.";
            return false;
        }
        bytes <<= shift;
    }
    criterion.isSize = true;
    criterion.size = bytes;
    return true;
}

/* Splits one mask token into its pattern and its criteria. */
bool ParseMaskToken(const std::string & text, FileMaskToken & token,
    std::string & error)
{
    token.text = text;
    token.directoryOnly = false;
    token.isPath = false;
    token.criteria.clear();

    std::string pattern;
    size_t i = 0;
    while (i < text.size() && text[i] != '<' && text[i] != '>' && text[i] != '=')
    {
        pattern += text[i];
        i++;
    }

    while (i < text.size())
    {
        MaskCriterion criterion;
        int op = -1;
        if (text[i] == '<')
        {
            op = 1;
        }
        else if (text[i] == '>')
        {
            op = 2;
        }
        else if (text[i] == '=')
        {
            op = 0;
        }
        if (op == -1)
        {
            error = "Unexpected character '" + std::string(1, text[i]) +
                "' in the file mask '" + text + "'.";
            return false;
        }
        i++;
        if (i < text.size() && text[i] == '=')
        {
            if (op == 1 || op == 2)
            {
                op += 2;                      /* '<=' and '>=' */
                i++;
            }
            else
            {
                error = "The operator in the file mask '" + text +
                    "' is not valid (use <, >, =, <= or >=).";
                return false;
            }
        }
        criterion.op = op;
        const size_t valueBegin = i;
        while (i < text.size() && text[i] != '<' && text[i] != '>' && text[i] != '=')
        {
            i++;
        }
        if (!ParseCriterionValue(text, valueBegin, i, criterion, error))
        {
            return false;
        }
        token.criteria.push_back(criterion);
    }

    if (!pattern.empty() && pattern[pattern.size() - 1] == '/')
    {
        token.directoryOnly = true;
        pattern.erase(pattern.size() - 1);
    }
    token.isPath = pattern.find('/') != std::string::npos;
    token.pattern = pattern.empty() ? "*" : pattern;
    return true;
}

} // namespace

bool FileMask::Parse(const std::string & text, std::string & error)
{
    include.clear();
    exclude.clear();
    std::string trimmed = text;
    while (!trimmed.empty() && (trimmed[0] == ' ' || trimmed[0] == '\"'))
    {
        trimmed.erase(0, 1);
    }
    while (!trimmed.empty() && (trimmed[trimmed.size() - 1] == ' ' ||
        trimmed[trimmed.size() - 1] == '\"'))
    {
        trimmed.erase(trimmed.size() - 1);
    }
    if (trimmed.empty())
    {
        return true;
    }

    std::vector<std::string> groups;
    std::string current;
    for (size_t i = 0; i < trimmed.size(); i++)
    {
        if (trimmed[i] == '|')
        {
            groups.push_back(current);
            current.clear();
        }
        else
        {
            current += trimmed[i];
        }
    }
    groups.push_back(current);
    if (groups.size() > 2)
    {
        error = "A file mask has at most one '|' (include masks|exclude masks).";
        return false;
    }

    for (size_t g = 0; g < groups.size(); g++)
    {
        std::vector<FileMaskToken> & target = g == 0 ? include : exclude;
        std::string mask;
        for (size_t i = 0; i <= groups[g].size(); i++)
        {
            const bool end = i == groups[g].size();
            if (!end && groups[g][i] != ';')
            {
                mask += groups[g][i];
                continue;
            }
            if (!mask.empty())
            {
                FileMaskToken token;
                if (!ParseMaskToken(mask, token, error))
                {
                    include.clear();
                    exclude.clear();
                    return false;
                }
                target.push_back(token);
                mask.clear();
            }
        }
    }
    if (include.empty() && exclude.empty())
    {
        error = "The file mask '" + text + "' is empty.";
        return false;
    }
    return true;
}

bool FileMask::Accepts(const std::string & name, bool isDirectory,
    unsigned long long size, unsigned long mtime,
    const std::string & relativePath) const
{
    for (size_t i = 0; i < exclude.size(); i++)
    {
        if (MatchesToken(exclude[i], name, isDirectory, size, mtime,
            relativePath, true))
        {
            return false;
        }
    }
    if (include.empty())
    {
        return true;
    }
    /* Does any include mask address directories at all? If not, include
     * masks never prune a directory. */
    bool anyDirectoryInclude = false;
    for (size_t i = 0; i < include.size(); i++)
    {
        if (include[i].directoryOnly || include[i].isPath)
        {
            anyDirectoryInclude = true;
        }
    }
    if (isDirectory && !anyDirectoryInclude)
    {
        return true;
    }
    for (size_t i = 0; i < include.size(); i++)
    {
        if (MatchesToken(include[i], name, isDirectory, size, mtime,
            relativePath, false))
        {
            return true;
        }
    }
    return false;
}

bool FileMask::Accepts(const std::string & name, bool isDirectory) const
{
    return Accepts(name, isDirectory, 0, 0, std::string());
}

std::string FileMask::Describe() const
{
    std::string result;
    for (size_t i = 0; i < include.size(); i++)
    {
        if (i != 0)
        {
            result += ";";
        }
        result += include[i].text;
    }
    if (!exclude.empty())
    {
        result += "|";
        for (size_t i = 0; i < exclude.size(); i++)
        {
            if (i != 0)
            {
                result += ";";
            }
            result += exclude[i].text;
        }
    }
    return result.empty() ? std::string("(none)") : result;
}

/* ------------------------------------------------------------------ *
 * SyncPlan                                                            *
 * ------------------------------------------------------------------ */

int SyncPlan::Count(SyncAction action) const
{
    int count = 0;
    for (size_t i = 0; i < items.size(); i++)
    {
        if (items[i].action == action)
        {
            count++;
        }
    }
    return count;
}

unsigned long long SyncPlan::Bytes(SyncAction action) const
{
    unsigned long long total = 0;
    for (size_t i = 0; i < items.size(); i++)
    {
        if (items[i].action != action || items[i].isDirectory)
        {
            continue;
        }
        total += action == SyncAction::Upload ? items[i].localSize : items[i].remoteSize;
    }
    return total;
}

bool SyncPlan::DeletesAnything() const
{
    return Count(SyncAction::DeleteLocal) != 0 ||
        Count(SyncAction::DeleteRemote) != 0;
}

namespace {

int ActionRank(SyncAction action)
{
    if (action == SyncAction::Upload || action == SyncAction::Download)
    {
        return 0;
    }
    if (action == SyncAction::Conflict)
    {
        return 1;
    }
    if (action == SyncAction::DeleteLocal || action == SyncAction::DeleteRemote)
    {
        return 2;
    }
    return 3; /* SyncAction::None: never interesting, sorted to the end */
}

int PathDepth(const std::string & path)
{
    int depth = 0;
    for (size_t i = 0; i < path.size(); i++)
    {
        if (path[i] == '/')
        {
            depth++;
        }
    }
    return depth;
}

bool ItemLess(const SyncItem & left, const SyncItem & right)
{
    const int rankLeft = ActionRank(left.action);
    const int rankRight = ActionRank(right.action);
    if (rankLeft != rankRight)
    {
        return rankLeft < rankRight;
    }
    if (rankLeft == 0 && left.isDirectory != right.isDirectory)
    {
        /* Directories before the files they contain. */
        return left.isDirectory;
    }
    if (rankLeft == 2)
    {
        /* Deletions deepest first, so that a directory is empty by the
         * time it is removed. */
        const int depthLeft = PathDepth(left.path);
        const int depthRight = PathDepth(right.path);
        if (depthLeft != depthRight)
        {
            return depthLeft > depthRight;
        }
    }
    return left.path < right.path;
}

} // namespace

void SyncPlan::Sort()
{
    std::stable_sort(items.begin(), items.end(), ItemLess);
}

/* ------------------------------------------------------------------ *
 * Paths                                                               *
 * ------------------------------------------------------------------ */

std::vector<std::string> SplitRelativePath(const std::string & path)
{
    std::vector<std::string> parts;
    std::string current;
    for (size_t i = 0; i < path.size(); i++)
    {
        if (path[i] == '/')
        {
            if (!current.empty())
            {
                parts.push_back(current);
                current.clear();
            }
        }
        else
        {
            current += path[i];
        }
    }
    if (!current.empty())
    {
        parts.push_back(current);
    }
    return parts;
}

std::string LocalPathForRelative(const std::string & root, const std::string & relative)
{
    std::string result = root;
    const std::vector<std::string> parts = SplitRelativePath(relative);
    for (size_t i = 0; i < parts.size(); i++)
    {
        result = JoinLocalPath(result, parts[i]);
    }
    return result;
}

std::string RemotePathForRelative(const std::string & root, const std::string & relative)
{
    std::string result = root;
    const std::vector<std::string> parts = SplitRelativePath(relative);
    for (size_t i = 0; i < parts.size(); i++)
    {
        result = JoinRemotePath(result, parts[i]);
    }
    return result;
}

/* ------------------------------------------------------------------ *
 * The planner                                                         *
 * ------------------------------------------------------------------ */

namespace {

class Planner
{
public:
    Planner(SyncFileSystem & localFs, SyncFileSystem & remoteFs,
        const std::string & localRoot, const std::string & remoteRoot,
        const SyncOptions & options, SyncPlan & plan) :
        mLocalFs(localFs), mRemoteFs(remoteFs), mLocalRoot(localRoot),
        mRemoteRoot(remoteRoot), mOptions(options), mPlan(plan)
    {
    }

    bool Run(std::string & error)
    {
        if (!PlanDirectory(std::string(), error))
        {
            return false;
        }
        /* A checksum that could not be computed is not an agreement between
         * two files: refusing the plan is safer than reporting as equal a
         * file nobody managed to read. */
        if (!mHashError.empty())
        {
            error = mHashError;
            return false;
        }
        return true;
    }

private:
    Planner(const Planner &);
    Planner & operator=(const Planner &);

    bool PlanDirectory(const std::string & relative, std::string & error)
    {
        std::string localError;
        std::string remoteError;
        std::vector<SyncEntry> localEntries;
        std::vector<SyncEntry> remoteEntries;
        const bool localOk = mLocalFs.ListDirectory(
            LocalPathForRelative(mLocalRoot, relative), localEntries, localError);
        const bool remoteOk = mRemoteFs.ListDirectory(
            RemotePathForRelative(mRemoteRoot, relative), remoteEntries, remoteError);

        if (!localOk && !remoteOk)
        {
            error = "Cannot read the local directory '" +
                LocalPathForRelative(mLocalRoot, relative) + "' (" + localError +
                ") or the remote directory '" +
                RemotePathForRelative(mRemoteRoot, relative) + "' (" + remoteError + ").";
            return false;
        }
        if (!localOk)
        {
            /* A missing local directory is created by a download, and is
             * an error for a synchronization that only uploads. */
            if (mOptions.mode == SyncMode::Remote)
            {
                error = "Cannot read the local directory '" +
                    LocalPathForRelative(mLocalRoot, relative) + "'" +
                    (localError.empty() ? std::string(".") : (" (" + localError + ")."));
                return false;
            }
            if (!relative.empty())
            {
                SyncItem item;
                item.action = SyncAction::Download;
                item.path = relative;
                item.isDirectory = true;
                item.reason = "the local directory does not exist yet";
                mPlan.items.push_back(item);
            }
            if (!remoteEntries.empty() && (relative.empty() || mOptions.recursive))
            {
                AddSubtree(mRemoteFs, relative, SyncAction::Download,
                    RemotePathForRelative(mRemoteRoot, relative), error);
            }
            return error.empty();
        }
        if (!remoteOk)
        {
            if (mOptions.mode == SyncMode::Local)
            {
                error = "Cannot read the remote directory '" +
                    RemotePathForRelative(mRemoteRoot, relative) + "'" +
                    (remoteError.empty() ? std::string(".") : (" (" + remoteError + ")."));
                return false;
            }
            if (!relative.empty())
            {
                SyncItem item;
                item.action = SyncAction::Upload;
                item.path = relative;
                item.isDirectory = true;
                item.reason = "the remote directory does not exist yet";
                mPlan.items.push_back(item);
            }
            if (!localEntries.empty() && (relative.empty() || mOptions.recursive))
            {
                AddSubtree(mLocalFs, relative, SyncAction::Upload,
                    LocalPathForRelative(mLocalRoot, relative), error);
            }
            return error.empty();
        }

        std::map<std::string, SyncEntry> localMap;
        std::map<std::string, SyncEntry> remoteMap;
        std::set<std::string> names;
        for (size_t i = 0; i < localEntries.size(); i++)
        {
            if (localEntries[i].name == "." || localEntries[i].name == "..")
            {
                continue;
            }
            localMap[localEntries[i].name] = localEntries[i];
            names.insert(localEntries[i].name);
        }
        for (size_t i = 0; i < remoteEntries.size(); i++)
        {
            if (remoteEntries[i].name == "." || remoteEntries[i].name == "..")
            {
                continue;
            }
            remoteMap[remoteEntries[i].name] = remoteEntries[i];
            names.insert(remoteEntries[i].name);
        }

        for (std::set<std::string>::const_iterator it = names.begin();
            it != names.end(); ++it)
        {
            const std::string & name = *it;
            std::map<std::string, SyncEntry>::const_iterator localIt = localMap.find(name);
            std::map<std::string, SyncEntry>::const_iterator remoteIt = remoteMap.find(name);
            const bool haveLocal = localIt != localMap.end();
            const bool haveRemote = remoteIt != remoteMap.end();
            const SyncEntry local = haveLocal ? localIt->second : SyncEntry();
            const SyncEntry remote = haveRemote ? remoteIt->second : SyncEntry();
            const bool isDirectory = (haveLocal && local.isDirectory) ||
                (haveRemote && remote.isDirectory);
            const std::string child = relative.empty() ? name : relative + "/" + name;

            const bool preferRemote = mOptions.mode == SyncMode::Local;
            const unsigned long long entrySize = preferRemote ?
                (haveRemote ? remote.size : local.size) :
                (haveLocal ? local.size : remote.size);
            const unsigned long entryTime = preferRemote ?
                ((haveRemote && remote.mtime != 0) ? remote.mtime : local.mtime) :
                ((haveLocal && local.mtime != 0) ? local.mtime : remote.mtime);
            if (!mOptions.mask.Accepts(name, isDirectory, entrySize, entryTime,
                child))
            {
                continue;
            }

            if (haveLocal && haveRemote && local.isDirectory == remote.isDirectory)
            {
                if (local.isDirectory)
                {
                    if (mOptions.recursive && !PlanDirectory(child, error))
                    {
                        return false;
                    }
                    continue;
                }
                CompareFile(child, local, remote);
                continue;
            }

            if (haveLocal && haveRemote)
            {
                SyncItem item;
                item.action = SyncAction::Conflict;
                item.path = child;
                item.isDirectory = isDirectory;
                item.localSize = local.size;
                item.remoteSize = remote.size;
                item.localTime = local.mtime;
                item.remoteTime = remote.mtime;
                item.reason = "it is a directory on one side and a file on the other";
                mPlan.items.push_back(item);
                continue;
            }

            /* Present on one side only. */
            if (haveLocal)
            {
                if (mOptions.mode == SyncMode::Local)
                {
                    AddObsolete(child, local, SyncAction::DeleteLocal, true);
                    continue;
                }
                if (mOptions.mode == SyncMode::Both && DeletedOnOtherSide(child, false))
                {
                    AddObsolete(child, local, SyncAction::DeleteLocal, false);
                    continue;
                }
                AddCopy(child, local, SyncAction::Upload,
                    mOptions.mode == SyncMode::Both ?
                        "it is new on the local side" : "it only exists locally",
                    LocalPathForRelative(mLocalRoot, child), error);
                continue;
            }

            if (mOptions.mode == SyncMode::Remote)
            {
                AddObsolete(child, remote, SyncAction::DeleteRemote, true);
                continue;
            }
            if (mOptions.mode == SyncMode::Both && DeletedOnOtherSide(child, true))
            {
                AddObsolete(child, remote, SyncAction::DeleteRemote, false);
                continue;
            }
            AddCopy(child, remote, SyncAction::Download,
                mOptions.mode == SyncMode::Both ?
                    "it is new on the remote side" : "it only exists remotely",
                RemotePathForRelative(mRemoteRoot, child), error);
        }
        return error.empty();
    }

    /* Adds a copy of 'entry' (a file) or of its whole subtree (a
     * directory) in the direction of 'action'. */
    void AddCopy(const std::string & relative, const SyncEntry & entry,
        SyncAction action, const std::string & reason, const std::string & sourcePath,
        std::string & error)
    {
        SyncItem item;
        item.action = action;
        item.path = relative;
        item.isDirectory = entry.isDirectory;
        item.localSize = entry.size;
        item.remoteSize = entry.size;
        item.localTime = entry.mtime;
        item.remoteTime = entry.mtime;
        item.reason = reason;
        mPlan.items.push_back(item);
        if (entry.isDirectory && mOptions.recursive)
        {
            SyncFileSystem & source = action == SyncAction::Upload ? mLocalFs : mRemoteFs;
            AddSubtree(source, relative, action, sourcePath, error);
        }
    }

    /* Copies every entry below a directory that exists on one side
     * only, so that a new subtree is planned as a whole. */
    void AddSubtree(SyncFileSystem & fs, const std::string & relative,
        SyncAction action, const std::string & path, std::string & error)
    {
        std::vector<SyncEntry> entries;
        std::string listError;
        if (!fs.ListDirectory(path, entries, listError))
        {
            return; /* unreadable subtree: reported when it is applied */
        }
        for (size_t i = 0; i < entries.size(); i++)
        {
            if (entries[i].name == "." || entries[i].name == "..")
            {
                continue;
            }
            const bool isDirectory = entries[i].isDirectory;
            const std::string child = relative.empty() ?
                entries[i].name : relative + "/" + entries[i].name;
            if (!mOptions.mask.Accepts(entries[i].name, isDirectory,
                entries[i].size, entries[i].mtime, child))
            {
                continue;
            }
            /* Without -recursive a directory is not descended into, and
             * an empty one is not created either. */
            if (isDirectory && !mOptions.recursive)
            {
                continue;
            }
            SyncItem item;
            item.action = action;
            item.path = child;
            item.isDirectory = isDirectory;
            item.localSize = entries[i].size;
            item.remoteSize = entries[i].size;
            item.localTime = entries[i].mtime;
            item.remoteTime = entries[i].mtime;
            item.reason = "part of a directory that exists on one side only";
            mPlan.items.push_back(item);
            if (isDirectory)
            {
                AddSubtree(fs, child, action,
                    action == SyncAction::Upload ?
                        LocalPathForRelative(mLocalRoot, child) :
                        RemotePathForRelative(mRemoteRoot, child), error);
            }
        }
    }

    /* Adds a deletion when the mode and the switches allow it.
     * 'mirror' is true for the one-directional modes, where the target
     * is made to match the source; in 'both' a deletion only happens
     * when the recorded state proves the entry was removed on the
     * other side. */
    void AddObsolete(const std::string & relative, const SyncEntry & entry,
        SyncAction action, bool mirror)
    {
        if (!mOptions.deleteObsolete)
        {
            return;
        }
        SyncItem item;
        item.action = action;
        item.path = relative;
        item.isDirectory = entry.isDirectory;
        item.localSize = entry.size;
        item.remoteSize = entry.size;
        item.localTime = entry.mtime;
        item.remoteTime = entry.mtime;
        item.reason = mirror ?
            "the other side does not have it" :
            "it was removed on the other side since the last synchronization";
        mPlan.items.push_back(item);
    }

    /* True when the recorded state says the entry used to exist on the
     * other side: it was deleted there, so deleting it here is the
     * synchronization and not a loss. */
    bool DeletedOnOtherSide(const std::string & relative, bool localIsMissing) const
    {
        if (mOptions.state == NULL || mOptions.state->Empty())
        {
            return false;
        }
        SyncStateEntry entry;
        if (!mOptions.state->Lookup(relative, entry))
        {
            return false;
        }
        return localIsMissing ? entry.localTime != 0 : entry.remoteTime != 0;
    }

    void CompareFile(const std::string & relative, const SyncEntry & local,
        const SyncEntry & remote)
    {
        SyncItem item;
        item.path = relative;
        item.isDirectory = false;
        item.localSize = local.size;
        item.remoteSize = remote.size;
        item.localTime = local.mtime;
        item.remoteTime = remote.mtime;

        if (mOptions.mode == SyncMode::Local)
        {
            if (Differs(relative, remote, local))
            {
                item.action = SyncAction::Download;
                item.reason = Reason(remote, local, "remote", "local");
            }
            else
            {
                item.action = SyncAction::None;
            }
            mPlan.items.push_back(item);
            return;
        }
        if (mOptions.mode == SyncMode::Remote)
        {
            if (Differs(relative, local, remote))
            {
                item.action = SyncAction::Upload;
                item.reason = Reason(local, remote, "local", "remote");
            }
            else
            {
                item.action = SyncAction::None;
            }
            mPlan.items.push_back(item);
            return;
        }

        /*
         * Both directions. The record of the previous synchronization
         * decides, and the criteria are not consulted - upstream enforces
         * the same rule for smBoth, and 'synchronize' refuses a criteria
         * value this branch could not honour.
         */
        SyncStateEntry recorded;
        const bool known = mOptions.state != NULL &&
            mOptions.state->Lookup(relative, recorded);
        auto resolveConflict = [&](SyncItem & conflictItem,
            const std::string & defaultReason)
        {
            if (mOptions.conflictPolicy == SyncConflictPolicy::Local)
            {
                conflictItem.action = SyncAction::Upload;
                conflictItem.reason =
                    "conflict resolved in favour of the local file";
                return;
            }
            if (mOptions.conflictPolicy == SyncConflictPolicy::Remote)
            {
                conflictItem.action = SyncAction::Download;
                conflictItem.reason =
                    "conflict resolved in favour of the remote file";
                return;
            }
            if (mOptions.conflictPolicy == SyncConflictPolicy::Newer)
            {
                if (local.mtime > remote.mtime)
                {
                    conflictItem.action = SyncAction::Upload;
                    conflictItem.reason =
                        "conflict resolved in favour of the newer local file";
                    return;
                }
                if (remote.mtime > local.mtime)
                {
                    conflictItem.action = SyncAction::Download;
                    conflictItem.reason =
                        "conflict resolved in favour of the newer remote file";
                    return;
                }
            }
            conflictItem.action = SyncAction::Conflict;
            conflictItem.reason = defaultReason;
        };

        if (!known)
        {
            if (local.mtime == remote.mtime && local.size == remote.size)
            {
                item.action = SyncAction::None;
            }
            else if (local.mtime == remote.mtime)
            {
                resolveConflict(item, "the timestamps are equal but the sizes "
                    "differ, and there is no previous synchronization to "
                    "compare with");
            }
            else if (local.mtime > remote.mtime)
            {
                item.action = SyncAction::Upload;
                item.reason = "the local file is newer and there is no previous "
                    "synchronization to compare with";
            }
            else
            {
                item.action = SyncAction::Download;
                item.reason = "the remote file is newer and there is no previous "
                    "synchronization to compare with";
            }
            mPlan.items.push_back(item);
            return;
        }

        const bool localChanged = local.mtime != recorded.localTime ||
            local.size != recorded.size;
        const bool remoteChanged = remote.mtime != recorded.remoteTime ||
            remote.size != recorded.size;
        if (localChanged && remoteChanged)
        {
            resolveConflict(item,
                "it changed on both sides since the last synchronization");
        }
        else if (localChanged)
        {
            item.action = SyncAction::Upload;
            item.reason = "it changed locally since the last synchronization";
        }
        else if (remoteChanged)
        {
            item.action = SyncAction::Download;
            item.reason = "it changed remotely since the last synchronization";
        }
        else
        {
            item.action = SyncAction::None;
        }
        mPlan.items.push_back(item);
    }

    /*
     * True when the source has to be copied over the target. What is
     * compared is what the criteria asked for, in upstream's order: the
     * timestamps first, then the sizes, and the contents last, because
     * reading two whole files is the expensive comparison of the three.
     */
    bool Differs(const std::string & relative, const SyncEntry & source,
        const SyncEntry & target) const
    {
        const SyncCriteria & criteria = mOptions.criteria;
        if (criteria.Empty())
        {
            return true;
        }
        bool differs = false;
        if (criteria.time)
        {
            /* Mirror mode resolves any difference toward the source,
             * including a newer target. */
            differs = mOptions.mirror ? source.mtime != target.mtime :
                source.mtime > target.mtime;
        }
        if (!differs && criteria.size)
        {
            differs = source.size != target.size;
        }
        if (!differs && criteria.checksum)
        {
            differs = !SameChecksum(relative);
        }
        return differs;
    }

    /* Compares the contents of the two files through their checksums. When a
     * side cannot be hashed the answer is "not the same", and the first
     * reason is remembered so that the plan is refused with it. */
    bool SameChecksum(const std::string & relative) const
    {
        std::string localHash;
        std::string remoteHash;
        const bool localOk = Hash(mLocalFs,
            LocalPathForRelative(mLocalRoot, relative), localHash);
        const bool remoteOk = Hash(mRemoteFs,
            RemotePathForRelative(mRemoteRoot, relative), remoteHash);
        return localOk && remoteOk && localHash == remoteHash;
    }

    /* One file's checksum, cached: the same file is read once however many
     * times the walk reaches it. */
    bool Hash(SyncFileSystem & fs, const std::string & path,
        std::string & hash) const
    {
        std::map<std::string, std::string> & cache =
            (&fs == &mLocalFs) ? mLocalHashes : mRemoteHashes;
        const std::map<std::string, std::string>::const_iterator found =
            cache.find(path);
        if (found != cache.end())
        {
            hash = found->second;
            return true;
        }
        std::string error;
        if (!fs.HashFile(path, hash, error))
        {
            if (mHashError.empty())
            {
                mHashError = "Cannot compare the checksum of '" + path +
                    "': " + error;
            }
            return false;
        }
        cache[path] = hash;
        return true;
    }

    /*
     * Why the source is copied over the target: the comparison the criteria
     * asked for that found the difference, with the sizes alongside because
     * they are the part of a plan worth reading.
     */
    std::string Reason(const SyncEntry & source, const SyncEntry & target,
        const char * sourceLabel, const char * targetLabel) const
    {
        const SyncCriteria & criteria = mOptions.criteria;
        const bool newer = mOptions.mirror ?
            source.mtime != target.mtime : source.mtime > target.mtime;
        std::string reason;
        if (criteria.time && newer)
        {
            reason = std::string("the ") + sourceLabel + " file is newer";
        }
        else if (criteria.size && source.size != target.size)
        {
            reason = "the sizes differ";
        }
        else if (criteria.checksum)
        {
            reason = std::string("the contents differ (the ") + sourceLabel +
                " checksum is not the " + targetLabel + " one)";
        }
        else if (criteria.Empty())
        {
            reason = std::string("every file is copied when the criteria are "
                "'none'");
        }
        else
        {
            reason = std::string("the ") + sourceLabel + " file differs";
        }
        if (source.size != target.size && reason != "the sizes differ")
        {
            char buffer[64];
            snprintf(buffer, sizeof(buffer), " (%llu against %llu bytes)",
                static_cast<unsigned long long>(source.size),
                static_cast<unsigned long long>(target.size));
            reason += buffer;
        }
        return reason;
    }

    SyncFileSystem & mLocalFs;
    SyncFileSystem & mRemoteFs;
    std::string mLocalRoot;
    std::string mRemoteRoot;
    const SyncOptions & mOptions;
    SyncPlan & mPlan;

    /* The checksums already computed on each side, and the first failure.
     * Mutable because comparing two files does not change the plan. */
    mutable std::map<std::string, std::string> mLocalHashes;
    mutable std::map<std::string, std::string> mRemoteHashes;
    mutable std::string mHashError;
};

} // namespace

bool PlanSynchronization(SyncFileSystem & localFs, SyncFileSystem & remoteFs,
    const std::string & localRoot, const std::string & remoteRoot,
    const SyncOptions & options, SyncPlan & plan, std::string & error)
{
    error.clear();
    if (localRoot.empty())
    {
        error = "The local directory of a synchronization is empty.";
        return false;
    }
    if (remoteRoot.empty())
    {
        error = "The remote directory of a synchronization is empty.";
        return false;
    }
    plan = SyncPlan();
    plan.mode = options.mode;
    plan.criteria = options.criteria;
    plan.mask = options.mask;
    plan.localRoot = localRoot;
    plan.remoteRoot = remoteRoot;

    Planner planner(localFs, remoteFs, localRoot, remoteRoot, options, plan);
    if (!planner.Run(error))
    {
        return false;
    }
    plan.Sort();
    return true;
}

/* ------------------------------------------------------------------ *
 * SyncState                                                           *
 * ------------------------------------------------------------------ */

namespace {

/* FNV-1a, only to name the state file after the pair of directories. */
std::string HashText(const std::string & text)
{
    unsigned long long hash = 1469598103934665603ULL;
    for (size_t i = 0; i < text.size(); i++)
    {
        hash ^= static_cast<unsigned char>(text[i]);
        hash *= 1099511628211ULL;
    }
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%016llx", hash);
    return std::string(buffer);
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

} // namespace

std::string SyncState::MakeKey(const std::string & host,
    const std::string & localRoot, const std::string & remoteRoot)
{
    return host + "|" + localRoot + "|" + remoteRoot;
}

std::string SyncState::DefaultPath(const std::string & key)
{
    const std::string config = ConfigDirectory();
    if (config.empty())
    {
        return std::string();
    }
    return config + "/sync/" + HashText(key) + ".state";
}

bool SyncState::Lookup(const std::string & relativePath, SyncStateEntry & entry) const
{
    std::map<std::string, SyncStateEntry>::const_iterator it =
        mEntries.find(relativePath);
    if (it == mEntries.end())
    {
        return false;
    }
    entry = it->second;
    return true;
}

void SyncState::Update(const std::string & relativePath, const SyncStateEntry & entry)
{
    mEntries[relativePath] = entry;
}

void SyncState::Remove(const std::string & relativePath)
{
    mEntries.erase(relativePath);
}

bool SyncState::Load(const std::string & path, std::string & error)
{
    mEntries.clear();
    if (path.empty())
    {
        return true; /* no configuration directory: a stateless comparison */
    }
    FILE * file = fopen(path.c_str(), "rb");
    if (file == NULL)
    {
        return true; /* no previous synchronization, not an error */
    }
    for (;;)
    {
        std::string line;
        char buffer[8192];
        bool anyRead = false;
        while (fgets(buffer, sizeof(buffer), file) != NULL)
        {
            anyRead = true;
            line.append(buffer);
            if (!line.empty() && line.back() == '\n')
            {
                break;
            }
            if (line.size() > 1024 * 1024)
            {
                break;
            }
        }
        if (!anyRead)
        {
            break;
        }
        while (!line.empty() && (line[line.size() - 1] == '\n' || line[line.size() - 1] == '\r'))
        {
            line.erase(line.size() - 1);
        }
        if (line.empty() || line[0] == '#')
        {
            continue;
        }
        std::vector<std::string> fields;
        std::string current;
        for (size_t i = 0; i < line.size(); i++)
        {
            if (line[i] == '\t')
            {
                fields.push_back(current);
                current.clear();
            }
            else
            {
                current += line[i];
            }
        }
        fields.push_back(current);
        if (fields.size() < 4)
        {
            continue;
        }
        SyncStateEntry entry;
        entry.localTime = static_cast<unsigned long>(strtoul(fields[1].c_str(), NULL, 10));
        entry.remoteTime = static_cast<unsigned long>(strtoul(fields[2].c_str(), NULL, 10));
        entry.size = strtoull(fields[3].c_str(), NULL, 10);
        mEntries[UnescapeValue(fields[0])] = entry;
    }
    fclose(file);
    (void)error;
    return true;
}

bool SyncState::Save(const std::string & path, std::string & error) const
{
    if (path.empty())
    {
        return true; /* nothing to remember, and not a failure */
    }
    const std::string directory = path.substr(0, path.find_last_of('/'));
    if (!directory.empty() && directory != path)
    {
        std::string createError;
        if (!CreatePrivateDirectory(directory, createError))
        {
            error = createError;
            return false;
        }
    }
    std::string tempPattern = path + ".tmp.XXXXXX";
    std::vector<char> tempBuf(tempPattern.begin(), tempPattern.end());
    tempBuf.push_back('\0');
    const int tempFd = mkstemp(tempBuf.data());
    if (tempFd < 0)
    {
        error = std::string("Cannot write the synchronization state '") + path + "'.";
        return false;
    }
    (void)fchmod(tempFd, 0600);
    const std::string tempPath(tempBuf.data());
    FILE * file = fdopen(tempFd, "wb");
    if (file == NULL)
    {
        close(tempFd);
        remove(tempPath.c_str());
        error = std::string("Cannot write the synchronization state '") + path + "'.";
        return false;
    }
    fprintf(file, "# LinSCP synchronization state, written %llu\n", NowSeconds());
    for (std::map<std::string, SyncStateEntry>::const_iterator it = mEntries.begin();
        it != mEntries.end(); ++it)
    {
        fprintf(file, "%s\t%lu\t%lu\t%llu\n", EscapeValue(it->first).c_str(),
            it->second.localTime, it->second.remoteTime, it->second.size);
    }
    const bool writeFailed = fflush(file) != 0 || ferror(file) != 0;
    const int closeRc = fclose(file);
    if (writeFailed || closeRc != 0 || rename(tempPath.c_str(), path.c_str()) != 0)
    {
        remove(tempPath.c_str());
        error = std::string("Cannot write the synchronization state '") + path + "'.";
        return false;
    }
    RestrictFileToUser(path);
    return true;
}

} // namespace linscp
