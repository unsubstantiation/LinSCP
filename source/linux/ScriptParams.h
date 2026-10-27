/*
 * ScriptParams: the expansions the LinSCP console applies to a command line
 * before the script interpreter sees it, plus the name resolution its command
 * table uses.
 *
 * Two independent mechanisms live here because both are pure text handling
 * that the front end and the unit tests share:
 *
 *   - ExpandScriptParameters() mirrors TConsoleRunner::ExpandCommand(): the
 *     script parameters %1%..%9%, the %TIMESTAMP% placeholder (optionally
 *     with a relative offset and an explicit format), and %ENVIRONMENT%
 *     variables.
 *   - FindPrefixedName() mirrors TScriptCommands::FindCommand(): a name is
 *     matched exactly first and then by an unambiguous prefix, so that
 *     'synch' means 'synchronize' while 'se' is refused as ambiguous (it could be 'session' or 'sessions').
 *
 * The functions never print and never touch the session.
 */

#ifndef LINSCP_SCRIPTPARAMS_H
#define LINSCP_SCRIPTPARAMS_H

#include <ctime>
#include <string>
#include <vector>

namespace linscp {

/* Result of FindPrefixedName when nothing or several names match. */
enum
{
    kNameNoMatch = -1,
    kNameAmbiguous = -2
};

/*
 * Resolves 'text' against 'names': an exact case-insensitive match wins,
 * otherwise a case-insensitive prefix that matches exactly one name resolves
 * to it. Returns the index in 'names', kNameNoMatch when nothing matches, or
 * kNameAmbiguous when several do; 'matches' then holds the candidates, comma
 * separated and in the order of 'names'.
 */
int FindPrefixedName(const std::vector<std::string> & names,
    const std::string & text, std::string & matches);

/* Convenience form for a caller that only needs the resolved name. Returns an
 * empty string when 'text' matches nothing, and sets 'ambiguous' with the
 * candidate list when it matches more than one. */
std::string ResolvePrefixedName(const std::vector<std::string> & names,
    const std::string & text, std::string & ambiguous);

/*
 * Formats a broken-down local time with the date format tokens LinSCP's
 * %TIMESTAMP#...% accepts: the quoted literal, 'c', 'yyyy', 'yy', 'mmmm',
 * 'mmm', 'mm', 'm', 'dddd', 'ddd', 'dd', 'd', 'hh', 'h', 'nn', 'n', 'ss',
 * 's', 'am/pm' and 'a/p'. A token that is not supported is copied verbatim,
 * because the placeholder may equally well be a literal text.
 */
std::string FormatTimestamp(const std::tm & time, const std::string & format);

/*
 * Reads a relative time specification the way upstream reads one: a whole
 * number followed by a unit ('S' seconds, 'N' minutes, 'H' hours, 'D' days,
 * 'Y' years), or the words 'today' and 'yesterday'. A unit followed by 'S'
 * ('2DS') snaps the result to the start of that unit. 'add' says whether the
 * amount is added to or subtracted from 'base'.
 */
bool TryRelativeTime(const std::string & text, std::time_t base, bool add,
    std::time_t & result, std::string & error);

/*
 * Expands one script command line:
 *
 *   %1% .. %9%        the script parameter of this run (up to nine)
 *   %TIMESTAMP%       the current local time as yyyymmddhhnnss, unless the
 *                     TIMESTAMP environment variable is set, in which case
 *                     the normal environment expansion applies to it
 *   %TIMESTAMP#fmt%   the same time formatted with 'fmt'; a signed relative
 *                     offset may precede the '#' ('%TIMESTAMP-1D#yyyymmdd%')
 *   %NAME%            an environment variable, left verbatim when it is not
 *                     set
 *
 * Expansion is not recursive: the substituted text is never scanned again, so
 * a parameter cannot introduce further placeholders.
 *
 * Returns false with 'error' set when a %TIMESTAMP% offset is malformed.
 * Upstream leaves such a placeholder in the text; failing instead is
 * deliberate, because a path that still contains '%TIMESTAMP+1Q#...' would
 * silently transfer files to the wrong place.
 */
bool ExpandScriptParameters(const std::string & line,
    const std::vector<std::string> & parameters, std::string & expanded,
    std::string & error);

/* Expands with no script parameters; used by callers that have none. */
bool ExpandScriptParameters(const std::string & line, std::string & expanded,
    std::string & error);

} // namespace linscp

#endif /* LINSCP_SCRIPTPARAMS_H */
