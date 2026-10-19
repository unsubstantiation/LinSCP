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

namespace linscp {

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
    bool IsVerbose() const { return mVerbose; }

    /* Reads one line from stdin; returns false at end of file. */
    bool ReadLine(const std::string & prompt, std::string & line);
    bool ReadPassword(const std::string & prompt, std::string & password);
    bool Confirm(const std::string & prompt, bool defaultYes);

    /* Session log file (line-oriented text format). */
    bool SetLogFile(const std::string & path, std::string & error);
    void LogTraffic(const void * data, size_t len, bool incoming);
    void CloseLogFile();

    /*
     * Structured action log ('-xmllog=<file>', the equivalent of the upstream
     * '/xmllog=' switch). Where the session log above holds the text an
     * operator reads, this one holds one XML element per event, so that a
     * program can read back what a script did: every command, its outcome,
     * every message and every transfer. The file is closed when the client
     * exits, which is when the root element is written.
     */
    bool SetActionLogFile(const std::string & path, std::string & error);
    void CloseActionLogFile();
    bool IsActionLogOpen() const { return mActionLog != NULL; }
    /* One element of the log; 'text' may be empty for a self-closing one. */
    void LogAction(const std::string & element, const std::string & attributes,
        const std::string & text = std::string());
    /* Escapes one value of an attribute of 'attributes' above. */
    static std::string EscapeActionText(const std::string & text);

    /* Progress display of a transfer. */
    void TransferStart(const std::string & fileName, uint64_t totalSize);
    void TransferProgress(uint64_t transferred);
    void TransferEnd(bool success);

private:
    Console();
    ~Console();
    Console(const Console &);
    Console & operator=(const Console &);

    bool mBatchMode;
    bool mVerbose;
    FILE * mLog;
    FILE * mActionLog;
    std::string mTransferName;
    uint64_t mTransferSize;
    unsigned long long mLastPermille;
};

} // namespace linscp

#endif /* LINSCP_CONSOLE_H */
