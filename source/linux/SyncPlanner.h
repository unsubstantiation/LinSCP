/*
 * SyncPlanner: compares two directory trees and turns the differences
 * into an explicit, reviewable plan.
 *
 * The planner never touches the file systems: it only reads directory
 * listings through the SyncFileSystem interface and returns a SyncPlan
 * describing what a synchronization would do. The caller decides
 * whether to print the plan ('synchronize -preview'), apply it, or ask
 * first. That is what makes '-delete' and bidirectional ('both')
 * synchronization safe: the destructive part is a line in a plan that
 * can be reviewed, not a side effect of walking a directory.
 *
 * Both sides are reached through the same interface, so the local
 * directory and the remote directory (native SFTP or a curl backend)
 * are compared by identical rules, and the planner can be tested with
 * two in-memory file systems.
 *
 * SyncState is the memory of a previous synchronization of the same
 * pair of directories. It is what turns 'both' from two sequential
 * copies into conflict detection: an entry that changed on both sides
 * since the last pass is reported as a conflict instead of being
 * silently overwritten in one direction.
 */

#ifndef LINSCP_SYNCPLANNER_H
#define LINSCP_SYNCPLANNER_H

#include <map>
#include <string>
#include <vector>

#include "TextMode.h"

namespace linscp {

/* Which side is the target of the synchronization.
 *
 *   Local  - the remote tree wins: changes are downloaded.
 *   Remote - the local tree wins: changes are uploaded.
 *   Both   - whichever side changed since the last synchronization
 *            wins; a change on both sides is a conflict. */
enum class SyncMode
{
    Local,
    Remote,
    Both
};

/*
 * What counts as a difference, as the three comparisons upstream's
 * synchronize flags carry (spNotByTime, spBySize, spByChecksum). A
 * '-criteria=' value switches them on and off, so every combination of
 * them is expressible: 'time' alone, 'size' alone, 'checksum' alone,
 * 'either' (time and size), or a list such as 'time,checksum'.
 *
 * With none of them set nothing is compared and every file counts as
 * different, which is upstream's '-criteria=none'.
 */
struct SyncCriteria
{
    bool time;      /* the source timestamp is newer than the target's */
    bool size;      /* the sizes differ, whatever the timestamps say */
    bool checksum;  /* the contents differ, compared when the rest agree */

    SyncCriteria() : time(true), size(false), checksum(false) {}

    bool Empty() const { return !time && !size && !checksum; }
    bool operator==(const SyncCriteria & other) const
        { return time == other.time && size == other.size &&
            checksum == other.checksum; }
    bool operator!=(const SyncCriteria & other) const
        { return !(*this == other); }
};

const char * SyncModeName(SyncMode mode);
/* The criteria as the word or list '-criteria=' takes: 'time', 'size',
 * 'either', 'checksum', 'none', 'time,checksum', ... */
std::string SyncCriteriaName(const SyncCriteria & criteria);
/* Parses upstream's value: 'none', 'either' (or 'both'), one of 'time',
 * 'size' and 'checksum', or a comma-separated list of those three. An
 * unknown word is refused with the words that are known. */
bool ParseSyncCriteria(const std::string & text, SyncCriteria & criteria,
    std::string & error);

/* One comparison attached to a mask token, LinSCP's extended mask
 * syntax: '*.tmp>1M' or '*.log>=2026-01-01'. */
struct MaskCriterion
{
    bool isSize;                  /* false: a time comparison */
    int op;                       /* 0 '=', 1 '<', 2 '>', 3 '<=', 4 '>=' */
    unsigned long long size;      /* bytes, when isSize */
    unsigned long time;           /* seconds since the epoch, when !isSize */
};

/* One mask token of a LinSCP file mask:
 *
 *   name mask       "*.tmp"         matches file names
 *   directory mask  "any/build/"      matches directories (trailing '/')
 *   path mask       "docs/\*.txt"   matches paths relative to the root
 *
 * plus any number of size/time criteria. */
struct FileMaskToken
{
    std::string text;             /* the token as written, for Describe() */
    std::string pattern;          /* the pattern without criteria/slash */
    bool directoryOnly;           /* written with a trailing '/' */
    bool isPath;                  /* the pattern contains a '/' */
    std::vector<MaskCriterion> criteria;

    FileMaskToken() : directoryOnly(false), isPath(false) {}
};

/* A set of include/exclude file masks.
 *
 * The syntax is LinSCP's:
 *
 *   "*.txt"                 include only files matching *.txt
 *   "|*.bak"                exclude files matching *.bak
 *   "*.txt|*.bak;*.tmp"     include *.txt except *.bak and *.tmp
 *
 * Several masks are separated by ';'. A mask without wildcards matches
 * that exact name. A mask ending in '/' matches directories only (by
 * its name or by trailing path components), so '|x/build/' prunes every
 * 'build' directory wherever it sits. A mask containing '/' elsewhere
 * matches the path of an entry relative to the transfer/synchronization
 * root. Size and time criteria ('*.txt>=1M', '*.log<2026-01-01') apply
 * to files only; a mask with a criterion never matches a directory.
 *
 * Exclusions are also applied to directories, which prunes a whole
 * subtree; an include mask never prunes a directory unless it is an
 * explicit directory or path mask. */
struct FileMask
{
    std::vector<FileMaskToken> include;
    std::vector<FileMaskToken> exclude;

    bool empty() const { return include.empty() && exclude.empty(); }
    bool Parse(const std::string & text, std::string & error);
    /* Full match with everything a transfer knows about an entry.
     * 'relativePath' is the entry path below the transfer root ('/'
     * separated, no leading or trailing '/'); size/mtime are what the
     * source side reported, 0 when unknown. */
    bool Accepts(const std::string & name, bool isDirectory,
        unsigned long long size, unsigned long mtime,
        const std::string & relativePath) const;
    /* Name-only match for callers that have no metadata. */
    bool Accepts(const std::string & name, bool isDirectory) const;
    std::string Describe() const;
};

/* One directory entry, as the planner sees it. */
struct SyncEntry
{
    std::string name;
    bool isDirectory;
    unsigned long long size;
    unsigned long mtime;      /* seconds since the epoch, 0 when unknown */
    unsigned long permissions;

    SyncEntry() : isDirectory(false), size(0), mtime(0), permissions(0) {}
};

/* Read-only view of one side of a synchronization. */
class SyncFileSystem
{
public:
    virtual ~SyncFileSystem() {}
    /* Entries of 'path' (without '.' and '..'), or false with 'error'. */
    virtual bool ListDirectory(const std::string & path,
        std::vector<SyncEntry> & entries, std::string & error) = 0;
    /* "local" or "remote": used in messages only. */
    virtual const char * Label() const = 0;
    /*
     * The checksum of one file as lowercase hexadecimal, for the
     * 'checksum' criteria. A side that cannot hash reports false with
     * 'error', and the planner then refuses the synchronization instead of
     * treating two files it could not read as equal: a difference it does
     * not see is a file it does not copy.
     */
    virtual bool HashFile(const std::string & path, std::string & hash,
        std::string & error)
    {
        (void)path;
        (void)hash;
        error = std::string(Label()) + " files cannot be compared by "
            "checksum in this build.";
        return false;
    }
};

enum class SyncAction
{
    None,          /* both sides already agree */
    Download,      /* remote -> local */
    Upload,        /* local -> remote */
    DeleteLocal,   /* obsolete: it is gone from the remote side */
    DeleteRemote,  /* obsolete: it is gone from the local side */
    Conflict       /* changed on both sides; needs a decision */
};

const char * SyncActionName(SyncAction action);

enum class SyncConflictPolicy
{
    Skip,          /* report as Conflict and leave untouched (default) */
    Local,         /* resolve file conflicts by uploading the local file */
    Remote,        /* resolve file conflicts by downloading the remote file */
    Newer          /* resolve file conflicts in favour of the newer side */
};

bool ParseSyncConflictPolicy(const std::string & text,
    SyncConflictPolicy & policy, std::string & error);
const char * SyncConflictPolicyName(SyncConflictPolicy policy);

/* One line of a plan: what to do with one path.
 *
 * 'path' is relative to the two synchronized roots and always uses '/',
 * so that it identifies the same entry on both sides no matter what the
 * local separator is. */
struct SyncItem
{
    SyncAction action;
    std::string path;
    bool isDirectory;
    unsigned long long localSize;
    unsigned long long remoteSize;
    unsigned long localTime;
    unsigned long remoteTime;
    std::string reason;    /* why this action was chosen */

    SyncItem() : action(SyncAction::None), isDirectory(false), localSize(0),
        remoteSize(0), localTime(0), remoteTime(0) {}
};

struct SyncPlan
{
    std::vector<SyncItem> items;
    SyncMode mode;
    SyncCriteria criteria;
    FileMask mask;
    std::string localRoot;
    std::string remoteRoot;

    /* Number of items with the given action. */
    int Count(SyncAction action) const;
    /* Bytes that the transfers of the given action would move. */
    unsigned long long Bytes(SyncAction action) const;
    /* True when applying the plan removes anything. */
    bool DeletesAnything() const;
    /* True when the plan needs a decision before it can be applied. */
    bool HasConflicts() const { return Count(SyncAction::Conflict) != 0; }
    /* Orders the items so that they can be applied in one pass:
     * directories before the files in them, transfers before deletions
     * and deletions from the deepest path upwards. */
    void Sort();
};

/* Everything the planner needs to know beyond the two roots. */
struct SyncOptions
{
    SyncMode mode;
    SyncCriteria criteria;
    FileMask mask;
    bool deleteObsolete;
    bool recursive;
    /* '-mirror': make the target match the source even where the target
     * is newer (local/remote modes only, like upstream). */
    bool mirror;
    /* Line-ending conversion applied to the files the plan moves. */
    TransferMode transferMode;
    /* Memory of the previous pass, or NULL for a stateless comparison.
     * 'both' only detects conflicts when there is a state, and only
     * deletes when the state proves an entry was removed on the other
     * side. */
    class SyncState * state;
    /* Policy for resolving file conflicts in 'both' mode. */
    SyncConflictPolicy conflictPolicy;

    SyncOptions() : mode(SyncMode::Local), deleteObsolete(false),
        recursive(true), mirror(false),
        transferMode(TransferMode::Binary), state(NULL),
        conflictPolicy(SyncConflictPolicy::Skip) {}
};

bool PlanSynchronization(SyncFileSystem & localFs, SyncFileSystem & remoteFs,
    const std::string & localRoot, const std::string & remoteRoot,
    const SyncOptions & options, SyncPlan & plan, std::string & error);

/* Splits a relative plan path ('a/b/c') into its components. */
std::vector<std::string> SplitRelativePath(const std::string & path);
/* Joins the components of a relative plan path with the local
 * separator, after 'root'. */
std::string LocalPathForRelative(const std::string & root, const std::string & relative);
/* Joins the components of a relative plan path with '/', after 'root'. */
std::string RemotePathForRelative(const std::string & root, const std::string & relative);

/* ------------------------------------------------------------------ *
 * SyncState: the outcome of the previous synchronization of one pair  *
 * of directories, used for conflict detection and safe deletion.      *
 * ------------------------------------------------------------------ */

struct SyncStateEntry
{
    unsigned long localTime;
    unsigned long remoteTime;
    unsigned long long size;

    SyncStateEntry() : localTime(0), remoteTime(0), size(0) {}
};

class SyncState
{
public:
    /* Identifies one pair of directories, including the server, so that
     * two sessions to the same host and path share their history and
     * different servers never do. */
    static std::string MakeKey(const std::string & host,
        const std::string & localRoot, const std::string & remoteRoot);
    /* File holding the state of that key, inside the configuration
     * directory. Empty when there is no configuration directory. */
    static std::string DefaultPath(const std::string & key);

    bool Load(const std::string & path, std::string & error);
    bool Save(const std::string & path, std::string & error) const;
    void Clear() { mEntries.clear(); }
    size_t Size() const { return mEntries.size(); }
    bool Empty() const { return mEntries.empty(); }

    bool Lookup(const std::string & relativePath, SyncStateEntry & entry) const;
    void Update(const std::string & relativePath, const SyncStateEntry & entry);
    void Remove(const std::string & relativePath);

private:
    std::map<std::string, SyncStateEntry> mEntries;
};

} // namespace linscp

#endif /* LINSCP_SYNCPLANNER_H */
