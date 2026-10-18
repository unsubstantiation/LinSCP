/*
 * Platform: the operating-system services the front end needs,
 * implemented for Linux (POSIX) in Platform.cpp.
 *
 * Everything above this layer (PathUtil, LocalFs, Console, Script,
 * ProtocolClient, Session) is written against these helpers plus the
 * C++ standard library. SSH, SFTP and SCP are served by libssh (Session + the native
 * SftpClient.cpp); the other protocols go through the curl
 * backend in ProtocolClient.cpp.
 */

#ifndef LINSCP_PLATFORM_H
#define LINSCP_PLATFORM_H

#include <ctime>
#include <string>
#include <vector>

namespace linscp {

/* One-time console setup. Safe to call before anything is printed. */
void InitConsole();

bool StdInIsTerminal();
bool StdOutIsTerminal();

/* Turns console echo off while alive (for password prompts). Restores
 * the previous mode on destruction; a no-op when there is no terminal. */
class EchoOff
{
public:
    EchoOff();
    ~EchoOff();
    bool Active() const { return mActive; }

private:
    EchoOff(const EchoOff &);
    EchoOff & operator=(const EchoOff &);

    bool mActive;
    int mFd;        /* descriptor the saved mode belongs to */
    void * mSaved;  /* the saved struct termios */
};

/* localtime_r behind one signature. */
bool LocalTime(std::time_t value, std::tm & result);

/* The user's home directory ($HOME), or an empty string when it cannot
 * be determined. */
std::string HomeDirectory();

/* Per-user configuration directory of the application, without a
 * trailing separator ($XDG_CONFIG_HOME/LinSCP or
 * ~/.config/LinSCP). Empty when no home directory is known. The
 * directory is not created. */
std::string ConfigDirectory();

/* The current user name ($USER or $LOGNAME), or an empty string. Used
 * as the default login name by 'open'. */
std::string CurrentUserName();

/* Directory for temporary files, without a trailing separator ($TMPDIR,
 * $TEMP, $TMP or /tmp). Empty when none is known. */
std::string TempDirectory();

/* Creates 'path' with all missing parents, accessible to the current
 * user only (0700). Used for the directories that hold a saved password
 * or an editor temporary file. */
bool CreatePrivateDirectory(const std::string & path, std::string & error);

/* Sets the permissions of 'path' so that only the current user can read
 * or write it (0600). Returns false when that is not possible. */
bool RestrictFileToUser(const std::string & path);

/* Sleeps for the given number of milliseconds. */
void SleepMilliseconds(unsigned milliseconds);

/* Installs a handler that records Ctrl-C (SIGINT) instead of letting it kill
 * the process, so that a long-running command such as 'keepuptodate' can stop
 * cleanly. Only the commands that watch Interrupted() install it: a transfer
 * engine whose loop does not consult the flag would run to completion with the
 * fatal default action replaced, so the rest keep it. Safe to call more than
 * once. */
void InstallInterruptHandler();
/* True once Ctrl-C has been seen by the installed handler. */
bool Interrupted();
/* Forgets a recorded Ctrl-C. A command that stops on one returns to its
 * caller with the flag still set, and the next command in the same process
 * would then stop before it started. */
void ClearInterrupt();

/* Sets the access/modification times (seconds since the epoch) of a
 * local file. Returns false on failure. */
bool SetFileTimes(const std::string & path, unsigned long atime,
    unsigned long mtime);

/* Parses an HTTP 'Last-Modified' header value ('Tue, 13 Oct 2026
 * 05:21:00 GMT') into seconds since the epoch. Returns 0 when the text
 * cannot be read. */
unsigned long ParseHttpDate(const std::string & text);

/* Parses the date column of an 'ls -l' entry, which is either a clock
 * time for a recent file ('Oct 13 05:21') or a year for an older one
 * ('Oct 13  2026'), into seconds since the epoch. Returns 0 when the
 * text cannot be read. */
unsigned long ParseListingDate(const std::string & monthName,
    const std::string & dayText, const std::string & timeOrYear);

/* A chunk delivered while a child is running. 'fromStderr' distinguishes
 * the progress/status stream from the captured stdout stream. The callback
 * runs in the parent process, never in the child, and must not retain the
 * pointed-to bytes after it returns. */
typedef void (*RunCaptureOutputFn)(const void * data, size_t len,
    bool fromStderr, void * ctx);

/* Runs args[0] with args[1..] without a shell, capturing everything the
 * child writes to stdout and stderr (read concurrently, so a child can
 * fill both pipes without deadlocking). If 'output' is non-NULL it also
 * receives each chunk as it is read, before the bytes are appended to 'out'
 * or 'err'. Returns the child's exit code, or -1 when the child could not
 * be started, in which case 'err' holds the reason. */
int RunCaptureWithOutput(const std::vector<std::string> & args,
    std::string & out, std::string & err, RunCaptureOutputFn output,
    void * ctx);

/* Convenience form for callers that only need the completed output. */
int RunCapture(const std::vector<std::string> & args, std::string & out,
    std::string & err);

/* Full path of an executable found on PATH, or an empty string. A name
 * containing a path separator is checked as given. */
std::string FindExecutableOnPath(const std::string & name);

/* Directory containing the running executable, or an empty string. */
std::string ExecutableDirectory();

/* Starts the graphical client (linscp-gui). This replaces the current
 * process and only returns on failure. */
bool LaunchGuiApplication(std::string & error);

/* Arguments of the system 'ssh' command client that open an interactive
 * session on the given server, without the program name. Exposed for the
 * unit tests and for the message shown when no terminal can be started. */
std::vector<std::string> BuildSshArguments(const std::string & userName,
    const std::string & hostName, int portNumber,
    const std::string & privateKeyFile);

/* Runs args[0] with args[1..] and waits for it to exit, with the child
 * inheriting the console (standard input, output and error are not
 * redirected). Returns the child's exit code, or -1 when it could not be
 * started, in which case 'error' holds the reason. Used to run the
 * external editor of the 'edit' command, which needs the terminal. */
int RunInteractive(const std::vector<std::string> & args, std::string & error);

/* Opens an interactive terminal on the given server: the system ssh in a
 * desktop terminal emulator (the terminal from LINSCP_TERMINAL,
 * otherwise the first of the common ones that is installed). Returns
 * false with 'error' set when nothing could be started. */
bool LaunchTerminalForServer(const std::string & userName,
    const std::string & hostName, int portNumber,
    const std::string & privateKeyFile, std::string & error);

} // namespace linscp

#endif /* LINSCP_PLATFORM_H */
