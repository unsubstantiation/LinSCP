/*
 * Console: all terminal input and output of the POSIX front end.
 *
 * Everything the client prints goes through this class, so that the
 * script/batch mode can suppress the interactive bits, and so that a
 * session log file can capture what the server sent.
 */

#ifndef LINSCP_CONSOLE_H
#define LINSCP_CONSOLE_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace linscp {

/* The '<name value="..."/>' parameters of an XML log action. */
typedef std::vector<std::pair<std::string, std::string> > XmlParams;

/* One '<file>' of an 'ls' or 'stat' XML log action, in the shape the
 * upstream schema (http://winscp.net/schema/session/1.0) defines: the
 * member is emitted only when it is known, which is what the 'has...'
 * flags and the empty strings say. 'name' stays empty for 'stat', whose
 * '<file>' carries no '<filename>'. */
struct XmlFileInfo
{
    XmlFileInfo() : type('-'), hasSize(false), size(0),
        hasModification(false), modification(0)
    {
    }

    std::string name;
    char type;                    /* 'D', 'L', '-' and the rest, as 'ls' */
    bool hasSize;
    unsigned long long size;
    bool hasModification;
    unsigned long modification;   /* seconds since the epoch */
    std::string permissions;      /* 'rwxr-xr-x', empty when unknown */
    std::string owner;
    std::string group;
};

class Console
{
public:
    static Console & Instance();

    /* Batch mode (a script is running): no prompts are asked, and
     * status messages are still printed. */
    void SetBatchMode(bool batch) { mBatchMode = batch; }
    bool IsBatchMode() const { return mBatchMode; }
    bool IsInteractive() const;

    void Write(const std::string & text);
    void WriteLine(const std::string & text = std::string());
    /* Progress/informational line, e.g. 'Reading directory... done'. */
    void Status(const std::string & text);
    /* Errors always go to stderr, and never to the session log. */
    void Error(const std::string & text);
    void Fatal(const std::string & text);
    /* Event log entries from the SSH layer (only with -verbose). */
    void LogEvent(const std::string & text);
    void SetVerbose(bool verbose) { mVerbose = verbose; }
    /* '-loglevel=-1': only errors and command output reach the terminal,
     * the status lines that narrate ordinary progress stay out of it. */
    void SetQuiet(bool quiet) { mQuiet = quiet; }
    bool IsVerbose() const { return mVerbose; }

    /* Reads one line from stdin; returns false at end of file. */
    bool ReadLine(const std::string & prompt, std::string & line);
    bool ReadPassword(const std::string & prompt, std::string & password);
    bool Confirm(const std::string & prompt, bool defaultYes);

    /* Session log file (line-oriented text format). */
    /* Opens the session log. A positive 'maxBytes' rotates the file
     * first when it has reached that size: up to 'maxCount' older files
     * are kept as '<path>.1' .. '<path>.<maxCount>', newest first, which
     * is upstream's '/logsize=[<count>*]<size>' policy. */
    bool SetLogFile(const std::string & path, std::string & error,
        unsigned long long maxBytes = 0, int maxCount = 1);
    void LogTraffic(const void * data, size_t len, bool incoming);
    void CloseLogFile();

    /*
     * Structured action log ('-xmllog=<file>', the equivalent of the upstream
     * '/xmllog=' switch). The document follows the upstream XML logging
     * schema, http://winscp.net/schema/session/1.0 (see
     * docs/winscp-session-1.0.xsd for the pinned description): one
     * '<session>' root, one '<group>' per script command (grouping is
     * always on, so a reader that follows the file knows a command has
     * finished when its group closes), one element per physical operation
     * ('upload', 'download', 'rm', 'mkdir', 'mv', 'cp', 'chmod', 'touch',
     * 'call', 'ls', 'stat', 'checksum', 'cwd') with '<name value="..."/>'
     * parameters and a '<result success="..."/>' child, and a '<failure>'
     * in the group when the command failed. Console output is not part of
     * the format and is not recorded. The root 'name' is whatever
     * XmlSessionName() learned before the first group was written, or
     * 'nosession'; the header is written lazily for that reason, and the
     * root is closed when the client exits.
     */
    bool SetActionLogFile(const std::string & path, std::string & error);
    void CloseActionLogFile();
    bool IsActionLogOpen() const { return mActionLog != NULL; }

    /* Names the '<session>' root. Only the name learned before the header
     * goes out (that is, before the first group of the connection that
     * carries the operations) is used; a later one would have to rewrite
     * bytes a continuous reader may already have consumed. */
    void XmlSessionName(const std::string & name);
    /* One script command: everything until XmlEndGroup() belongs to it.
     * 'name' must already have its passwords masked. */
    void XmlBeginGroup(const std::string & name);
    void XmlEndGroup();
    /* The '<failure>' of a failed command, one '<message>' per entry.
     * The caller masks the messages; TakeActionErrors() hands over the
     * errors Error() collected since the group began. */
    void XmlFailure(const std::vector<std::string> & messages);
    std::vector<std::string> TakeActionErrors();
    /* One operation element. 'error' becomes the '<message>' of a failed
     * result; 'recursive' is the attribute upstream uses when one
     * operation acted on a whole tree. */
    void XmlAction(const std::string & element, const XmlParams & params,
        bool success, const std::string & error = std::string(),
        bool recursive = false);
    /* An 'ls' element: its '<files>' container of '<file>' entries. */
    void XmlActionFiles(const std::string & element, const XmlParams & params,
        const std::vector<XmlFileInfo> & files, bool success,
        const std::string & error = std::string());
    /* A 'stat' element: one '<file>' after the parameters. */
    void XmlActionFile(const std::string & element, const XmlParams & params,
        const XmlFileInfo & file, bool success,
        const std::string & error = std::string());

    /* Attribute values escape a newline as '&#10;' (it would otherwise be
     * folded to a space by the reader), element text keeps it; both drop
     * a carriage return and the control characters XML cannot hold. This
     * is upstream's XmlAttributeEscape/XmlEscape pair. */
    static std::string EscapeXmlAttr(const std::string & text);
    static std::string EscapeXmlText(const std::string & text);
    /* Kept so a caller that escaped for the old attribute-string form
     * says what it did: it is the attribute escape. */
    static std::string EscapeActionText(const std::string & text)
    {
        return EscapeXmlAttr(text);
    }
    /* The one timestamp spelling of the format: UTC, millisecond field
     * always present, 'Z' suffix ('2021-12-03T14:25:10.204Z'). */
    static std::string XmlTimestamp(unsigned long epochSeconds);
    static std::string XmlTimestampNow();

    /* Progress display of a transfer. */
    void TransferStart(const std::string & fileName, uint64_t totalSize);
    void TransferProgress(uint64_t transferred);
    void TransferEnd(bool success);

private:
    Console();
    ~Console();
    Console(const Console &);
    Console & operator=(const Console &);

    /* The '<session>' header, on first use; see SetActionLogFile(). */
    void XmlEnsureHeader();
    void XmlWriteLine(int depth, const std::string & text);
    void XmlWriteParams(int depth, const XmlParams & params);
    void XmlWriteFile(int depth, const XmlFileInfo & file, bool withName);
    void XmlWriteResult(int depth, bool success, const std::string & error);

    bool mBatchMode;
    bool mVerbose;
    bool mQuiet;
    FILE * mLog;
    FILE * mActionLog;
    bool mXmlHeaderWritten;
    bool mXmlInGroup;
    /* The '<group>' line of the command that opens the session is held
     * back until the header can carry that session's name: upstream
     * begins the 'open' group on the terminal it creates, so its
     * '<session>' is never 'nosession' for a run that connected. */
    std::string mXmlPendingGroup;
    std::string mXmlSessionName;
    std::vector<std::string> mXmlErrors;
    std::string mTransferName;
    uint64_t mTransferSize;
    unsigned long long mLastPermille;
};

} // namespace linscp

#endif /* LINSCP_CONSOLE_H */
