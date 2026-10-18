#include "ScriptParams.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "Platform.h"

namespace linscp {

namespace {

std::string ToLowerAscii(const std::string & text)
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

bool EqualsIgnoreCase(const std::string & left, const std::string & right)
{
    return left.size() == right.size() && ToLowerAscii(left) == ToLowerAscii(right);
}

std::string Trim(const std::string & text)
{
    size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
    {
        return std::string();
    }
    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

/* Case-insensitive search, starting at 'from'. */
size_t FindIgnoreCase(const std::string & haystack, const std::string & needle,
    size_t from)
{
    if (needle.empty() || from >= haystack.size())
    {
        return std::string::npos;
    }
    const std::string text = ToLowerAscii(haystack);
    const std::string wanted = ToLowerAscii(needle);
    return text.find(wanted, from);
}

void ReplaceAll(std::string & text, const std::string & needle,
    const std::string & value)
{
    if (needle.empty())
    {
        return;
    }
    size_t position = 0;
    while ((position = text.find(needle, position)) != std::string::npos)
    {
        text.replace(position, needle.size(), value);
        position += value.size();
    }
}

/* Case-insensitive replacement of an exact placeholder. */
void ReplaceAllIgnoreCase(std::string & text, const std::string & needle,
    const std::string & value)
{
    if (needle.empty())
    {
        return;
    }
    const std::string lower = ToLowerAscii(text);
    const std::string wanted = ToLowerAscii(needle);
    std::string result;
    size_t position = 0;
    size_t match;
    while ((match = lower.find(wanted, position)) != std::string::npos)
    {
        result += text.substr(position, match - position) + value;
        position = match + wanted.size();
    }
    result += text.substr(position);
    text.swap(result);
}

std::string EnvironmentVariable(const std::string & name)
{
    const char * value = getenv(name.c_str());
    return value != NULL ? std::string(value) : std::string();
}

bool LookupEnvironmentVariable(const std::string & name, std::string & value)
{
    const char * found = getenv(name.c_str());
    if (found == NULL)
    {
        return false;
    }
    value = found;
    return true;
}

const char * const kMonthNames[] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

const char * const kDayNames[] = {
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
};

int DaysInMonth(int year, int month)
{
    static const int lengths[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (month < 1 || month > 12)
    {
        return 31;
    }
    if (month == 2)
    {
        const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        return leap ? 29 : 28;
    }
    return lengths[month - 1];
}

/* A token of the date format, longest first, so that 'yyyy' wins over 'yy'. */
struct FormatToken
{
    const char * text;
    int kind;
};

enum
{
    KindYear4, KindYear2, KindMonthLong, KindMonthShort, KindMonth2, KindMonth1,
    KindDayLong, KindDayShort, KindDay2, KindDay1, KindHour2, KindHour1,
    KindMinute2, KindMinute1, KindSecond2, KindSecond1, KindAmPm, KindAmPmShort,
    KindFullFormat
};

const FormatToken kFormatTokens[] = {
    { "yyyy", KindYear4 },
    { "mmmm", KindMonthLong },
    { "dddd", KindDayLong },
    { "am/pm", KindAmPm },
    { "a/p", KindAmPmShort },
    { "mmm", KindMonthShort },
    { "ddd", KindDayShort },
    { "yy", KindYear2 },
    { "mm", KindMonth2 },
    { "dd", KindDay2 },
    { "hh", KindHour2 },
    { "nn", KindMinute2 },
    { "ss", KindSecond2 },
    { "c", KindFullFormat },
    { "m", KindMonth1 },
    { "d", KindDay1 },
    { "h", KindHour1 },
    { "n", KindMinute1 },
    { "s", KindSecond1 }
};

} // namespace

int FindPrefixedName(const std::vector<std::string> & names,
    const std::string & text, std::string & matches)
{
    matches.clear();
    const std::string wanted = ToLowerAscii(text);
    if (wanted.empty())
    {
        return kNameNoMatch;
    }

    for (size_t i = 0; i < names.size(); i++)
    {
        if (ToLowerAscii(names[i]) == wanted)
        {
            return static_cast<int>(i);
        }
    }

    int found = kNameNoMatch;
    int count = 0;
    for (size_t i = 0; i < names.size(); i++)
    {
        const std::string name = ToLowerAscii(names[i]);
        if (wanted.size() <= name.size() && name.compare(0, wanted.size(), wanted) == 0)
        {
            if (count != 0)
            {
                matches += ", ";
            }
            matches += names[i];
            count++;
            found = static_cast<int>(i);
        }
    }
    if (count == 0)
    {
        return kNameNoMatch;
    }
    if (count > 1)
    {
        return kNameAmbiguous;
    }
    return found;
}

std::string ResolvePrefixedName(const std::vector<std::string> & names,
    const std::string & text, std::string & ambiguous)
{
    std::string matches;
    const int index = FindPrefixedName(names, text, matches);
    ambiguous.clear();
    if (index == kNameAmbiguous)
    {
        ambiguous = matches;
        return std::string();
    }
    if (index < 0)
    {
        return std::string();
    }
    return names[static_cast<size_t>(index)];
}

std::string FormatTimestamp(const std::tm & time, const std::string & format)
{
    std::string result;
    size_t i = 0;
    char buffer[64];
    /* Delphi's FormatDateTime reads its tokens case-insensitively, so
     * 'yyyy-mm-dd' and 'YYYY-MM-DD' mean the same thing. The literal text
     * that is not a token keeps the case it was written in. */
    const std::string lowered = ToLowerAscii(format);

    /* With an AM/PM marker in the format, 'h' and 'hh' count hours on a
     * twelve-hour clock, as FormatDateTime does. Quoted text is skipped. */
    bool hasAmPm = false;
    for (size_t scan = 0; scan < lowered.size(); )
    {
        if (format[scan] == '"' || format[scan] == '\'')
        {
            const char quote = format[scan];
            scan++;
            while (scan < format.size() && format[scan] != quote)
            {
                scan++;
            }
            scan++;
            continue;
        }
        if (lowered.compare(scan, 5, "am/pm") == 0 ||
            lowered.compare(scan, 3, "a/p") == 0)
        {
            hasAmPm = true;
            break;
        }
        scan++;
    }

    while (i < format.size())
    {
        const char c = format[i];
        size_t matchedLength = 0;
        if (c == '"' || c == '\'')
        {
            /* Quoted literal text; the quote itself is not kept and a
             * doubled quote stands for one literal quote. */
            const char quote = c;
            i++;
            while (i < format.size())
            {
                if (format[i] == quote)
                {
                    if (i + 1 < format.size() && format[i + 1] == quote)
                    {
                        result += quote;
                        i += 2;
                        continue;
                    }
                    i++;
                    break;
                }
                result += format[i];
                i++;
            }
            continue;
        }

        for (size_t t = 0; t < sizeof(kFormatTokens) / sizeof(kFormatTokens[0]); t++)
        {
            const size_t length = strlen(kFormatTokens[t].text);
            if (lowered.compare(i, length, kFormatTokens[t].text) != 0)
            {
                continue;
            }
            matchedLength = length;
            switch (kFormatTokens[t].kind)
            {
                case KindYear4:
                    snprintf(buffer, sizeof(buffer), "%04d", time.tm_year + 1900);
                    result += buffer;
                    break;
                case KindYear2:
                    snprintf(buffer, sizeof(buffer), "%02d", (time.tm_year + 1900) % 100);
                    result += buffer;
                    break;
                case KindMonthLong:
                    result += kMonthNames[time.tm_mon % 12];
                    break;
                case KindMonthShort:
                    result += std::string(kMonthNames[time.tm_mon % 12], 0, 3);
                    break;
                case KindMonth2:
                    snprintf(buffer, sizeof(buffer), "%02d", time.tm_mon + 1);
                    result += buffer;
                    break;
                case KindMonth1:
                    snprintf(buffer, sizeof(buffer), "%d", time.tm_mon + 1);
                    result += buffer;
                    break;
                case KindDayLong:
                    result += kDayNames[time.tm_wday % 7];
                    break;
                case KindDayShort:
                    result += std::string(kDayNames[time.tm_wday % 7], 0, 3);
                    break;
                case KindDay2:
                    snprintf(buffer, sizeof(buffer), "%02d", time.tm_mday);
                    result += buffer;
                    break;
                case KindDay1:
                    snprintf(buffer, sizeof(buffer), "%d", time.tm_mday);
                    result += buffer;
                    break;
                case KindHour2:
                case KindHour1:
                {
                    int hour = time.tm_hour;
                    if (hasAmPm)
                    {
                        hour %= 12;
                        if (hour == 0)
                        {
                            hour = 12;
                        }
                    }
                    snprintf(buffer, sizeof(buffer),
                        kFormatTokens[t].kind == KindHour2 ? "%02d" : "%d", hour);
                    result += buffer;
                    break;
                }
                case KindMinute2:
                    snprintf(buffer, sizeof(buffer), "%02d", time.tm_min);
                    result += buffer;
                    break;
                case KindMinute1:
                    snprintf(buffer, sizeof(buffer), "%d", time.tm_min);
                    result += buffer;
                    break;
                case KindSecond2:
                    snprintf(buffer, sizeof(buffer), "%02d", time.tm_sec);
                    result += buffer;
                    break;
                case KindSecond1:
                    snprintf(buffer, sizeof(buffer), "%d", time.tm_sec);
                    result += buffer;
                    break;
                case KindAmPm:
                case KindAmPmShort:
                {
                    const bool pm = time.tm_hour >= 12;
                    if (kFormatTokens[t].kind == KindAmPm)
                    {
                        result += pm ? "PM" : "AM";
                    }
                    else
                    {
                        result += pm ? "P" : "A";
                    }
                    break;
                }
                case KindFullFormat:
                    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
                        time.tm_year + 1900, time.tm_mon + 1, time.tm_mday,
                        time.tm_hour, time.tm_min, time.tm_sec);
                    result += buffer;
                    break;
                default:
                    break;
            }
            break;
        }
        if (matchedLength == 0)
        {
            /* Not a token: literal text (separators, in particular). */
            result += c;
            i++;
        }
        else
        {
            i += matchedLength;
        }
    }
    return result;
}

bool TryRelativeTime(const std::string & text, std::time_t base, bool add,
    std::time_t & result, std::string & error)
{
    error.clear();
    const std::string trimmed = Trim(text);
    if (trimmed.empty())
    {
        error = "a relative time needs an amount and a unit "
            "(for example '-1D', '+2H', 'today' or 'yesterday')";
        return false;
    }

    long amount = 0;
    char unit = 0;
    bool startOfUnit = false;

    if (EqualsIgnoreCase(trimmed, "today"))
    {
        amount = 0;
        unit = 'D';
        startOfUnit = true;
    }
    else if (EqualsIgnoreCase(trimmed, "yesterday"))
    {
        amount = 1;
        unit = 'D';
        startOfUnit = true;
    }
    else
    {
        size_t i = 0;
        while (i < trimmed.size() && isdigit(static_cast<unsigned char>(trimmed[i])))
        {
            i++;
        }
        if (i == 0 || i >= trimmed.size())
        {
            error = "'" + trimmed + "' is not a relative time "
                "(expected for example '1D', '2H' or '30N')";
            return false;
        }
        amount = strtol(trimmed.substr(0, i).c_str(), NULL, 10);
        std::string rest = Trim(trimmed.substr(i));
        if (rest.size() == 2 && (rest[1] == 'S' || rest[1] == 's'))
        {
            startOfUnit = true;
            rest = rest.substr(0, 1);
        }
        if (rest.size() != 1)
        {
            error = "'" + trimmed + "' has no single time unit after the number";
            return false;
        }
        unit = static_cast<char>(toupper(static_cast<unsigned char>(rest[0])));
    }

    if (!add)
    {
        amount = -amount;
    }

    std::tm parts;
    if (!LocalTime(base, parts))
    {
        error = "the current time could not be read";
        return false;
    }

    /* The offset counts on from the current moment; only a trailing 'S'
     * (and 'today'/'yesterday') snaps the result to the start of the unit.
     * Minutes and hours used to drop the finer fields unconditionally, so
     * '%TIMESTAMP+2H#hh:nn%' at 06:38 printed 08:00 and '+1N' lost the
     * seconds, which contradicted the documented rule and the day and year
     * units next to them. */
    switch (unit)
    {
        case 'S':
            parts.tm_sec += static_cast<int>(amount);
            break;
        case 'N':
            if (startOfUnit)
            {
                parts.tm_sec = 0;
            }
            parts.tm_min += static_cast<int>(amount);
            break;
        case 'H':
            if (startOfUnit)
            {
                parts.tm_sec = 0;
                parts.tm_min = 0;
            }
            parts.tm_hour += static_cast<int>(amount);
            break;
        case 'D':
            if (startOfUnit)
            {
                parts.tm_sec = 0;
                parts.tm_min = 0;
                parts.tm_hour = 0;
            }
            parts.tm_mday += static_cast<int>(amount);
            break;
        case 'Y':
            if (startOfUnit)
            {
                parts.tm_sec = 0;
                parts.tm_min = 0;
                parts.tm_hour = 0;
                parts.tm_mon = 0;
                parts.tm_mday = 1;
            }
            parts.tm_year += static_cast<int>(amount);
            /* Keep a 29 February in a common year at the end of February. */
            parts.tm_mday = parts.tm_mday < 1 ? 1 :
                (parts.tm_mday > DaysInMonth(parts.tm_year + 1900, parts.tm_mon + 1)
                    ? DaysInMonth(parts.tm_year + 1900, parts.tm_mon + 1)
                    : parts.tm_mday);
            break;
        default:
            error = "'" + std::string(1, unit) + "' is not a time unit of this "
                "build (S seconds, N minutes, H hours, D days, Y years)";
            return false;
    }

    parts.tm_isdst = -1;
    const std::time_t shifted = mktime(&parts);
    if (shifted == static_cast<std::time_t>(-1))
    {
        error = "'" + trimmed + "' is outside the representable time range";
        return false;
    }
    result = shifted;
    return true;
}

bool ExpandScriptParameters(const std::string & line,
    const std::vector<std::string> & parameters, std::string & expanded,
    std::string & error)
{
    error.clear();
    expanded = line;
    if (expanded.find('%') == std::string::npos)
    {
        return true;
    }

    /* Script parameters, like the upstream loop over the parameter list. */
    for (size_t i = 0; i < parameters.size() && i < 9; i++)
    {
        ReplaceAll(expanded, "%" + std::to_string(i + 1) + "%", parameters[i]);
    }

    /* The plain timestamp placeholder, unless the caller already set it. */
    if (EnvironmentVariable("TIMESTAMP").empty())
    {
        const std::time_t now = time(NULL);
        std::tm parts;
        if (LocalTime(now, parts))
        {
            ReplaceAllIgnoreCase(expanded, "%TIMESTAMP%",
                FormatTimestamp(parts, "yyyymmddhhnnss"));
        }
    }

    /* The timestamp placeholder with a format and an optional offset. */
    size_t offset = 0;
    while (true)
    {
        const size_t start = FindIgnoreCase(expanded, "%TIMESTAMP", offset);
        if (start == std::string::npos)
        {
            break;
        }
        const size_t afterName = start + strlen("%TIMESTAMP");
        const size_t close = expanded.find('%', afterName);
        if (close == std::string::npos)
        {
            break;
        }
        const char after = afterName < expanded.size() ? expanded[afterName] : '\0';
        if (after != '+' && after != '-' && after != '#')
        {
            /* Not a timestamp placeholder but an environment variable whose
             * name starts with 'TIMESTAMP'; the last loop expands those. */
            offset = afterName;
            continue;
        }

        const size_t hash = expanded.find('#', afterName);
        if (hash == std::string::npos || hash > close)
        {
            /* There is an offset but no format to apply it to. Upstream
             * leaves the text alone; refusing it here is deliberate, since
             * a placeholder nobody asked about would otherwise reach the
             * remote side as part of a file name. */
            error = "'" + expanded.substr(start, close - start + 1) +
                "' is not a valid timestamp placeholder; use %TIMESTAMP%, "
                "%TIMESTAMP+1D#yyyymmdd% or %TIMESTAMP-2H#yyyy-mm-dd%.";
            return false;
        }

        std::time_t moment = time(NULL);
        const size_t formatStart = hash + 1;
        if (hash > afterName)
        {
            const char sign = expanded[afterName];   /* '+' or '-' here */
            const std::string spec = expanded.substr(afterName + 1, hash - afterName - 1);
            std::string timeError;
            if (!TryRelativeTime(spec, moment, sign == '+', moment, timeError))
            {
                error = "The time offset '" + spec + "' in '" +
                    expanded.substr(start, close - start + 1) + "' is not valid: " +
                    timeError + ".";
                return false;
            }
        }

        std::tm parts;
        if (!LocalTime(moment, parts))
        {
            offset = afterName;
            continue;
        }
        const std::string value =
            FormatTimestamp(parts, expanded.substr(formatStart, close - formatStart));
        expanded.replace(start, close - start + 1, value);
        offset = start + value.size();
    }

    /* Environment variables last, so that a variable can hold a format. */
    size_t position = 0;
    while (true)
    {
        const size_t start = expanded.find('%', position);
        if (start == std::string::npos)
        {
            break;
        }
        const size_t close = expanded.find('%', start + 1);
        if (close == std::string::npos)
        {
            break;
        }
        const std::string name = expanded.substr(start + 1, close - start - 1);
        if (name.empty() || name.find('%') != std::string::npos)
        {
            position = start + 1;
            continue;
        }
        std::string value;
        if (!LookupEnvironmentVariable(name, value))
        {
            /* Unset: kept verbatim, as upstream does. */
            position = close + 1;
            continue;
        }
        expanded.replace(start, close - start + 1, value);
        position = start + value.size();
    }
    return true;
}

bool ExpandScriptParameters(const std::string & line, std::string & expanded,
    std::string & error)
{
    return ExpandScriptParameters(line, std::vector<std::string>(), expanded,
        error);
}

} // namespace linscp
