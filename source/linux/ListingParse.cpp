/*
 * ListingParse: see ListingParse.h. These helpers were the private
 * parsing half of the curl backend and are now shared with the native
 * FTP engine, so that a listing from LIST and one from MLSD produce the
 * same entries.
 */

#include "ListingParse.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>

#include "Platform.h"

namespace linscp {

ListingEntry::ListingEntry()
    : typeKnown(false), isDir(false), permissions(0100644), size(0),
      timeKnown(false), mtime(0)
{
}

bool SplitLongListing(const std::string & line, std::vector<std::string> & fields)
{
    fields.clear();
    std::istringstream stream(line);
    std::string field;
    while (fields.size() < 8 && (stream >> field))
    {
        fields.push_back(field);
    }
    if (fields.size() < 8)
    {
        return false;
    }
    std::string rest;
    std::getline(stream, rest);
    size_t first = rest.find_first_not_of(" \t");
    if (first == std::string::npos)
    {
        return false;
    }
    fields.push_back(rest.substr(first));
    return true;
}

bool LooksLikePermissions(const std::string & text)
{
    if (text.size() != 10)
    {
        return false;
    }
    const char types[] = "-dlbcps";
    if (strchr(types, text[0]) == NULL)
    {
        return false;
    }
    for (size_t i = 1; i < 10; i++)
    {
        if (strchr("rwxstST-", text[i]) == NULL)
        {
            return false;
        }
    }
    return true;
}

unsigned long PermissionsFromString(const std::string & text)
{
    /* The type column decides the file type. Reading only 'd' lost every
     * other kind: a symbolic link arrived as a regular file, so a caller
     * that transfers or compares by type acted on the wrong thing. These
     * are the same type bits PermissionsString() prints. */
    unsigned long mode;
    switch (text.empty() ? '-' : text[0])
    {
    case 'd': mode = 0040000UL; break;
    case 'l': mode = 0120000UL; break;
    case 'c': mode = 0020000UL; break;
    case 'b': mode = 0060000UL; break;
    case 'p': mode = 0010000UL; break;
    case 's': mode = 0140000UL; break;
    default:  mode = 0100000UL; break;
    }
    static const unsigned long bits[9] = {
        0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001
    };
    for (size_t i = 0; i < 9 && i + 1 < text.size(); i++)
    {
        char c = text[i + 1];
        if (c == 'r' || c == 'w' || c == 'x' || c == 's' || c == 'S' ||
            c == 't' || c == 'T')
        {
            mode |= bits[i];
        }
    }
    /* 's'/'S' and 't'/'T' carry the special bits as well as the execute
     * bit the letter stands in for. An upper-case letter means the
     * execute bit is absent, so only the special bit is left. Dropping
     * these made PermissionsString(PermissionsFromString(x)) != x for
     * every setuid, setgid and sticky entry a server can list. */
    if (text.size() > 3 && (text[3] == 's' || text[3] == 'S'))
    {
        mode |= 04000UL;
        if (text[3] == 'S')
        {
            mode &= ~0100UL;
        }
    }
    if (text.size() > 6 && (text[6] == 's' || text[6] == 'S'))
    {
        mode |= 02000UL;
        if (text[6] == 'S')
        {
            mode &= ~0010UL;
        }
    }
    if (text.size() > 9 && (text[9] == 't' || text[9] == 'T'))
    {
        mode |= 01000UL;
        if (text[9] == 'T')
        {
            mode &= ~0001UL;
        }
    }
    return mode;
}

bool ParseUnixListingLine(const std::string & line, ListingEntry & entry)
{
    std::vector<std::string> fields;
    if (!SplitLongListing(line, fields) || !LooksLikePermissions(fields[0]))
    {
        return false;
    }
    entry.name = fields[8];
    entry.typeKnown = true;
    entry.isDir = fields[0][0] == 'd';
    entry.permissions = PermissionsFromString(fields[0]);
    /* A symbolic link line carries its target after the name. The target
     * says where the link points, not what the link is called, so it is
     * not part of the name a later 'get' or 'rm' would be given. Only a
     * link line has a target to remove: a regular file may be called
     * 'odd -> name.txt' and keeps its whole name. Doing this here rather
     * than in one backend keeps the three producers of an entry in
     * agreement, which is what this file exists for. */
    if ((entry.permissions & 0170000UL) == 0120000UL)
    {
        const std::string::size_type arrow = entry.name.find(" -> ");
        if (arrow != std::string::npos)
        {
            entry.name = entry.name.substr(0, arrow);
        }
        /* The size column of a link line is the length of the target
         * path, which is neither the entry's size nor a directory's. */
        entry.isDir = false;
    }
    const unsigned long fileType = entry.permissions & 0170000UL;
    if (fileType == 0020000UL || fileType == 0060000UL)
    {
        entry.size = 0;
    }
    else
    {
        if (fields[4].empty())
        {
            return false;
        }
        for (size_t i = 0; i < fields[4].size(); ++i)
        {
            if (fields[4][i] < '0' || fields[4][i] > '9')
            {
                return false;
            }
        }
        errno = 0;
        char * end = NULL;
        const unsigned long long parsedSize =
            strtoull(fields[4].c_str(), &end, 10);
        if (errno != 0 || end == NULL || *end != '\0')
        {
            return false;
        }
        entry.size = parsedSize;
    }
    entry.mtime = ParseListingDate(fields[5], fields[6], fields[7]);
    entry.timeKnown = entry.mtime != 0;
    return true;
}

std::string PermissionsString(unsigned long permissions)
{
    const char type =
        (permissions & 0170000UL) == 0040000UL ? 'd' :
        (permissions & 0170000UL) == 0120000UL ? 'l' :
        (permissions & 0170000UL) == 0020000UL ? 'c' :
        (permissions & 0170000UL) == 0060000UL ? 'b' :
        (permissions & 0170000UL) == 0010000UL ? 'p' :
        (permissions & 0170000UL) == 0140000UL ? 's' : '-';
    std::string text(1, type);
    static const char rwx[9] = { 'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x' };
    static const unsigned long bits[9] = {
        0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001
    };
    for (size_t i = 0; i < 9; i++)
    {
        text += (permissions & bits[i]) != 0 ? rwx[i] : '-';
    }
    if (permissions & 04000UL) { text[3] = text[3] == 'x' ? 's' : 'S'; }
    if (permissions & 02000UL) { text[6] = text[6] == 'x' ? 's' : 'S'; }
    if (permissions & 01000UL) { text[9] = text[9] == 'x' ? 't' : 'T'; }
    return text;
}

/* ---- DOS/IIS listing parser ---------------------------------------------
 *
 * IIS and other DOS-syntactic FTP servers emit:
 *
 *   03-25-23  11:22AM       <DIR>          dirname
 *   07-14-22  04:00PM             12345    filename
 *
 * Date is MM-DD-YY or MM-DD-YYYY, time is HH:MMAM/PM, <DIR> marks a
 * directory, otherwise the size follows, then the name.
 *
 * Some servers put a blank between the time and the meridiem ('04:00 PM')
 * and some leave the meridiem out altogether ('04:00'). Both are read:
 * the meridiem was the last word of the time column, and a listing that
 * separates it from the time made the size column look like a word of
 * its own, so the size came out as zero and the name carried the size
 * in front of it.
 */

bool LooksLikeDosListing(const std::string & line)
{
    /* A DOS date starts with a two-digit month, a dash, two-digit day,
     * a dash and a two- or four-digit year.  Accept either separator
     * (- or /).  The check is deliberately narrow to avoid false
     * positives on arbitrary text. */
    if (line.size() < 18)
    {
        return false;
    }
    char c0 = line[0], c1 = line[1];
    if (c0 < '0' || c0 > '9' || c1 < '0' || c1 > '9')
    {
        return false;
    }
    if (line[2] != '-' && line[2] != '/')
    {
        return false;
    }
    /* Day: two digits */
    char c3 = line[3], c4 = line[4];
    if (c3 < '0' || c3 > '9' || c4 < '0' || c4 > '9')
    {
        return false;
    }
    if (line[5] != '-' && line[5] != '/')
    {
        return false;
    }
    /* Year: two or four digits */
    for (size_t i = 6; i < 10 && i < line.size(); i++)
    {
        if (line[i] < '0' || line[i] > '9')
        {
            /* Accept two-digit year followed by whitespace */
            if (i == 8 && (line[i] == ' ' || line[i] == '\t'))
            {
                break;
            }
            return false;
        }
    }
    return true;
}

namespace {

bool ParseDosDate(const std::string & dateStr, const std::string & timeStr,
    unsigned long & mtime)
{
    /* dateStr: MM-DD-YY or MM-DD-YYYY  timeStr: HH:MMAM or HH:MM PM */
    if (dateStr.size() < 8)
    {
        return false;
    }
    int month = 0, day = 0, year = 0;
    /* Parse month-day-year */
    const char * ds = dateStr.c_str();
    month = (ds[0] - '0') * 10 + (ds[1] - '0');
    day = (ds[3] - '0') * 10 + (ds[4] - '0');
    if (dateStr.size() == 10)
    {
        year = (ds[6] - '0') * 1000 + (ds[7] - '0') * 100 +
               (ds[8] - '0') * 10 + (ds[9] - '0');
    }
    else if (dateStr.size() == 8)
    {
        year = (ds[6] - '0') * 10 + (ds[7] - '0');
        year += (year < 70) ? 2000 : 1900;
    }
    else
    {
        return false;
    }
    if (month < 1 || month > 12 || day < 1 || day > 31)
    {
        return false;
    }

    /*
     * Parse the time: 'HH:MM', with the meridiem attached ('HH:MMAM') or
     * in the column next to it ('HH:MM' then 'AM'), and without one at
     * all ('HH:MM', a 24-hour clock).
     *
     * The digits are checked before they are used. Reading '??' as a
     * number produced an hour of some value out of the question marks,
     * and mktime() folded it into a moment the file never had.
     */
    int hour = 0, minute = 0;
    bool isPM = false;
    bool haveMeridiem = false;
    const char * ts = timeStr.c_str();
    if (timeStr.size() >= 5)
    {
        if (ts[0] < '0' || ts[0] > '9' || ts[1] < '0' || ts[1] > '9' ||
            ts[3] < '0' || ts[3] > '9' || ts[4] < '0' || ts[4] > '9')
        {
            return false;
        }
        hour = (ts[0] - '0') * 10 + (ts[1] - '0');
        if (ts[2] != ':')
        {
            return false;
        }
        minute = (ts[3] - '0') * 10 + (ts[4] - '0');
        if (hour > 23 || minute > 59)
        {
            return false;
        }
        /* The meridiem, when the server wrote one. */
        std::string tail = timeStr.substr(5);
        while (!tail.empty() && (tail[0] == ' ' || tail[0] == '\t'))
        {
            tail.erase(0, 1);
        }
        if (tail.size() >= 2)
        {
            const char a = static_cast<char>(toupper(
                static_cast<unsigned char>(tail[0])));
            const char b = static_cast<char>(toupper(
                static_cast<unsigned char>(tail[1])));
            if (a == 'A' && b == 'M')
            {
                haveMeridiem = true;
                isPM = false;
            }
            else if (a == 'P' && b == 'M')
            {
                haveMeridiem = true;
                isPM = true;
            }
        }
    }
    if (haveMeridiem)
    {
        if (hour < 1 || hour > 12)
        {
            /* A twelve-hour clock does not have an hour 0 or 13. */
            return false;
        }
        if (isPM && hour < 12) hour += 12;
        if (!isPM && hour == 12) hour = 0;
    }

    struct tm tm = {};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_isdst = -1;
    time_t t = mktime(&tm);
    if (t == static_cast<time_t>(-1))
    {
        return false;
    }
    mtime = static_cast<unsigned long>(t);
    return true;
}

} // namespace

bool ParseDosListingLine(const std::string & line, ListingEntry & entry)
{
    if (!LooksLikeDosListing(line))
    {
        return false;
    }
    std::istringstream stream(line);
    std::string dateStr, timeStr, dirOrSize;
    if (!(stream >> dateStr >> timeStr >> dirOrSize))
    {
        return false;
    }

    /*
     * The meridiem is a word of its own in some listings: '04:00 PM'
     * puts it in the column where the size belongs. Reading the size
     * from that column then gave the size of zero and left the size in
     * front of the file name, so the entry described a file called
     * '12345    filename' of no size at all.
     */
    {
        std::string upper = dirOrSize;
        for (size_t i = 0; i < upper.size(); i++)
        {
            upper[i] = static_cast<char>(toupper(
                static_cast<unsigned char>(upper[i])));
        }
        if (upper == "AM" || upper == "PM")
        {
            std::string next;
            if (!(stream >> next))
            {
                return false;
            }
            dirOrSize = next;
            /* The meridiem belongs to the time column. */
            timeStr += " " + upper;
        }
    }

    /* The name is everything after the size/DIR field, trimmed. */
    std::string rest;
    std::getline(stream, rest);
    size_t first = rest.find_first_not_of(" \t");
    if (first == std::string::npos)
    {
        return false;
    }
    std::string name = rest.substr(first);
    /* Trim trailing whitespace */
    while (!name.empty() && (name.back() == ' ' || name.back() == '\t' ||
           name.back() == '\r' || name.back() == '\n'))
    {
        name.pop_back();
    }
    if (name.empty() || name == "." || name == "..")
    {
        return false;
    }

    entry.name = name;
    entry.typeKnown = true;

    if (dirOrSize == "<DIR>" || dirOrSize == "<dir>")
    {
        entry.isDir = true;
        entry.permissions = 0040755UL;
        entry.size = 0;
    }
    else
    {
        entry.isDir = false;
        entry.permissions = 0100644UL;
        /* The size column is a number. std::stoull() accepts a sign and
         * turns '-1' into a huge size, so the digits are checked first. */
        bool numeric = !dirOrSize.empty();
        for (size_t i = 0; i < dirOrSize.size(); i++)
        {
            if (dirOrSize[i] < '0' || dirOrSize[i] > '9')
            {
                numeric = false;
                break;
            }
        }
        try
        {
            entry.size = numeric ? std::stoull(dirOrSize) : 0;
        }
        catch (...)
        {
            entry.size = 0;
        }
    }

    entry.longname = line;
    entry.timeKnown = ParseDosDate(dateStr, timeStr, entry.mtime);
    return true;
}

/* ---- VMS (OpenVMS) listing parser ----------------------------------------
 *
 * VMS FTP servers emit:
 *
 *   FILENAME.TXT;1    25  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)
 *   SUBDIR.DIR;1       3  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)
 *
 * The version (;N) follows the extension.  The name is everything before
 * the first semicolon.  A .DIR extension marks a directory.
 */

namespace {

/* VMS servers disagree about the case of a listing: Multinet writes
 * upper-case months and protections, UCX and several emulators write
 * lower case. Detection and parsing have to agree on that, or a
 * lower-case listing is not recognized as one and the caller is left
 * with a directory it cannot read. */
std::string UpperAscii(const std::string & text)
{
    std::string upper = text;
    for (size_t i = 0; i < upper.size(); i++)
    {
        if (upper[i] >= 'a' && upper[i] <= 'z')
        {
            upper[i] = static_cast<char>(upper[i] - 'a' + 'A');
        }
    }
    return upper;
}

int VmsMonthIndex(const std::string & text)
{
    static const char * months[] = {
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
    };
    const std::string upper = UpperAscii(text);
    for (int i = 0; i < 12; i++)
    {
        if (upper == months[i])
        {
            return i;
        }
    }
    return -1;
}

/* All digits, and at least one of them: what a numeric column has to be
 * before it is turned into a number. Reading a '[' or a '-' as a digit
 * produced a negative hour that mktime() silently folded into another
 * day, so an entry claimed a time it never had. */
bool AllDigits(const std::string & text)
{
    if (text.empty())
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
    return true;
}

} // namespace

bool LooksLikeVmsListing(const std::string & line)
{
    /* A VMS listing has a semicolon-delimited version, a numeric size,
     * a date in DD-MON-YYYY format and an owner in brackets.  At minimum
     * it needs the semicolon, a space, digits, a space and a date-like
     * token. */
    if (line.empty() || line[0] == ' ')
    {
        return false;
    }
    size_t semi = line.find(';');
    if (semi == std::string::npos || semi < 2)
    {
        return false;
    }
    /* After the semicolon there must be a version number, then whitespace
     * and a size.  Be conservative: look for a DD-MON-YYYY date pattern
     * further along. */
    size_t dash = line.find('-', semi + 1);
    if (dash == std::string::npos || dash + 11 > line.size())
    {
        return false;
    }
    /* The month abbreviation after the dash, in whichever case the
     * server wrote it. */
    if (VmsMonthIndex(line.substr(dash + 1, 3)) < 0)
    {
        return false;
    }
    /* Look for the bracketed owner */
    return line.find('[') != std::string::npos &&
           line.find(']') != std::string::npos;
}

namespace {

int VmsMonthFromText(const std::string & text)
{
    return VmsMonthIndex(text);
}

/*
 * A VMS protection field is four comma-separated classes of letters
 * inside parentheses, as in '(RWED,RWED,RE,RE)': system, owner, group
 * and world. Read, write and execute map onto the POSIX bits of the
 * matching class; delete has no bit of its own, so it is shown through
 * the write bit, which is the closest thing a chmod-only client has.
 * A listing whose field is absent or is not four classes keeps the
 * conservative default rather than a mode guessed from part of it.
 */
unsigned long VmsPermissionsFromProtection(const std::string & line, bool isDir)
{
    const unsigned long fallback = isDir ? 0040755UL : 0100644UL;
    const size_t open = line.rfind('(');
    const size_t close = line.rfind(')');
    if (open == std::string::npos || close == std::string::npos ||
        close < open + 2)
    {
        return fallback;
    }
    const std::string field = UpperAscii(line.substr(open + 1, close - open - 1));
    std::vector<std::string> classes;
    size_t start = 0;
    while (true)
    {
        const size_t comma = field.find(',', start);
        classes.push_back(field.substr(start,
            comma == std::string::npos ? std::string::npos : comma - start));
        if (comma == std::string::npos)
        {
            break;
        }
        start = comma + 1;
    }
    if (classes.size() != 4)
    {
        return fallback;
    }
    /* An empty class is a real answer, not a malformed one: it grants
     * that class nothing, as in '(RWED,RWED,,)' where only the system and
     * the owner may reach the file. Anything but the protection letters
     * is not a field this can read. */
    for (size_t i = 0; i < classes.size(); i++)
    {
        if (classes[i].find_first_not_of("RWED-") != std::string::npos)
        {
            return fallback;
        }
    }
    /* classes[1..3] are owner, group and world. */
    static const unsigned int shift[3] = { 6, 3, 0 };
    unsigned long mode = isDir ? 0040000UL : 0100000UL;
    for (size_t i = 0; i < 3; i++)
    {
        const std::string & letters = classes[i + 1];
        unsigned long bits = 0;
        if (letters.find('R') != std::string::npos) { bits |= 04UL; }
        if (letters.find('W') != std::string::npos ||
            letters.find('D') != std::string::npos) { bits |= 02UL; }
        if (letters.find('E') != std::string::npos) { bits |= 01UL; }
        mode |= bits << shift[i];
    }
    return mode;
}

} // namespace

bool ParseVmsListingLine(const std::string & line, ListingEntry & entry)
{
    if (!LooksLikeVmsListing(line))
    {
        return false;
    }

    /* Split on semicolon to get the version, then parse name.ext;N SIZE
     * DD-MON-YYYY HH:MM:SS [OWNER] (perms) */
    size_t semi = line.find(';');
    /* The version number after the semicolon */
    size_t versionEnd = line.find_first_of(" \t", semi + 1);
    if (versionEnd == std::string::npos)
    {
        return false;
    }

    /* The name with extension is everything before the semicolon. */
    std::string nameWithExt = line.substr(0, semi);

    /* Skip the version and read the size. */
    size_t pos = versionEnd + 1;
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
    {
        pos++;
    }
    size_t sizeStart = pos;
    while (pos < line.size() && line[pos] >= '0' && line[pos] <= '9')
    {
        pos++;
    }
    if (pos == sizeStart)
    {
        return false;
    }
    unsigned long long size = 0;
    try
    {
        size = std::stoull(line.substr(sizeStart, pos - sizeStart));
    }
    catch (...)
    {
        size = 0;
    }

    /* Skip whitespace, then read the date: DD-MON-YYYY */
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
    {
        pos++;
    }
    size_t dateStart = pos;
    /* Find the space before the time */
    size_t dateEnd = line.find(' ', pos);
    if (dateEnd == std::string::npos || dateEnd < dateStart + 11)
    {
        return false;
    }
    std::string datePart = line.substr(dateStart, dateEnd - dateStart);

    /* Parse DD-MON-YYYY */
    int day = 0, month = 0, year = 0;
    size_t d1 = datePart.find('-');
    if (d1 == std::string::npos || d1 < 1 || d1 > 2)
    {
        return false;
    }
    if (!AllDigits(datePart.substr(0, d1)))
    {
        return false;
    }
    for (size_t i = 0; i < d1; i++)
    {
        day = day * 10 + (datePart[i] - '0');
    }
    size_t d2 = datePart.find('-', d1 + 1);
    if (d2 == std::string::npos)
    {
        return false;
    }
    month = VmsMonthFromText(datePart.substr(d1 + 1, d2 - d1 - 1));
    if (month < 0)
    {
        return false;
    }
    const std::string yearText = datePart.substr(d2 + 1);
    if (!AllDigits(yearText) || yearText.size() != 4)
    {
        return false;
    }
    for (size_t i = 0; i < yearText.size(); i++)
    {
        year = year * 10 + (yearText[i] - '0');
    }
    if (day < 1 || day > 31 || year < 1970 || year > 2106)
    {
        return false;
    }

    /* Parse time HH:MM:SS. A listing that stops at the date, or whose
     * next column is not a time, has no time to report: saying otherwise
     * hands mktime() letters as digits and it folds them into some other
     * moment, which then drives a 'synchronize -criteria=time' decision. */
    pos = dateEnd + 1;
    int hour = 0, minute = 0, second = 0;
    bool haveTime = false;
    if (pos + 5 <= line.size() && line[pos + 2] == ':' &&
        AllDigits(line.substr(pos, 2)) && AllDigits(line.substr(pos + 3, 2)))
    {
        hour = (line[pos] - '0') * 10 + (line[pos + 1] - '0');
        minute = (line[pos + 3] - '0') * 10 + (line[pos + 4] - '0');
        if (pos + 8 <= line.size() && line[pos + 5] == ':' &&
            AllDigits(line.substr(pos + 6, 2)))
        {
            second = (line[pos + 6] - '0') * 10 + (line[pos + 7] - '0');
            haveTime = hour <= 23 && minute <= 59 && second <= 59;
        }
        else
        {
            haveTime = hour <= 23 && minute <= 59;
        }
    }

    unsigned long mtime = 0;
    if (haveTime)
    {
        struct tm tm = {};
        tm.tm_year = year - 1900;
        tm.tm_mon = month;
        tm.tm_mday = day;
        tm.tm_hour = hour;
        tm.tm_min = minute;
        tm.tm_sec = second;
        tm.tm_isdst = -1;
        time_t t = mktime(&tm);
        if (t != static_cast<time_t>(-1))
        {
            mtime = static_cast<unsigned long>(t);
        }
    }

    /* Determine whether it is a directory (.DIR extension). */
    bool isDir = false;
    std::string name = nameWithExt;
    std::string upperExt;
    size_t dot = nameWithExt.rfind('.');
    if (dot != std::string::npos)
    {
        upperExt = nameWithExt.substr(dot + 1);
        for (size_t i = 0; i < upperExt.size(); i++)
        {
            if (upperExt[i] >= 'a' && upperExt[i] <= 'z')
            {
                upperExt[i] = static_cast<char>(upperExt[i] - 'a' + 'A');
            }
        }
        if (upperExt == "DIR")
        {
            isDir = true;
            name = nameWithExt.substr(0, dot);
        }
    }

    if (name.empty() || name == "." || name == "..")
    {
        return false;
    }

    entry.name = name;
    entry.typeKnown = true;
    entry.isDir = isDir;
    /* The protection field is the permissions this listing actually
     * carries; a fixed 0644 threw away the one column of the line that
     * says who may do what. */
    entry.permissions = VmsPermissionsFromProtection(line, isDir);
    entry.size = isDir ? 0 : size;
    entry.timeKnown = mtime != 0;
    entry.mtime = mtime;
    entry.longname = line;
    return true;
}

bool ParseAnyListingLine(const std::string & line, ListingEntry & entry)
{
    if (ParseUnixListingLine(line, entry))
    {
        return true;
    }
    if (ParseDosListingLine(line, entry))
    {
        return true;
    }
    if (ParseVmsListingLine(line, entry))
    {
        return true;
    }
    return false;
}

} // namespace linscp
