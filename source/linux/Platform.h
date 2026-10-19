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
#include <map>
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
 * process and only returns on failure. On a console a human is reading, the
 * client is asked to open its page in the desktop's browser as well, which is
 * how -gui shows a window on a Wayland session. */
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

/* A path probe, so that the display-server detection below can be tested
 * without a compositor: it answers whether a file exists. */
typedef bool (*PathExistsFn)(const std::string & path, void * ctx);

/*
 * The display servers a window of this process could be shown on, as one
 * environment describes them.
 *
 * Wayland is reachable when the compositor's socket sits in
 * $XDG_RUNTIME_DIR: the one $WAYLAND_DISPLAY names, or the default
 * 'wayland-0' when that variable is unset and a compositor left its socket
 * behind (which is how a session started by a service manager, or a client
 * re-executed by one, still finds the display). X11 is reachable when
 * $DISPLAY is set.
 *
 * Both have to be asked about, and a program that opens a window has to be
 * one the session can show: a Wayland session exports no $DISPLAY at all
 * where XWayland is not running, and a Wayland-only terminal under X11 exits
 * before it maps anything.
 */
struct DesktopSession
{
    DesktopSession() : wayland(false), x11(false),
        waylandWithoutRuntimeDirectory(false) {}

    bool wayland;
    bool x11;
    /* The socket the detection looked for, empty when there was no
     * directory to look in. Named in the error message, because 'the
     * compositor was not found' is only useful if it says where. */
    std::string waylandSocketPath;
    /* The socket name to add to the environment of a child, when it was
     * found without $WAYLAND_DISPLAY. Empty when the environment named it
     * already, or when there is no Wayland session. */
    std::string inferredWaylandDisplay;
    /* $WAYLAND_DISPLAY is set but $XDG_RUNTIME_DIR is not, so neither this
     * client nor the program it starts can locate the socket. */
    bool waylandWithoutRuntimeDirectory;
};

/* The detection above, from an environment the caller supplies: the unit
 * tests hand in their own variables and their own path probe. */
DesktopSession DetectDesktopSession(
    const std::map<std::string, std::string> & environment,
    PathExistsFn pathExists, void * ctx);

/* One terminal this client knows how to start: the program, the option that
 * makes it run a command instead of a login shell, and the display server it
 * can draw on - "" for either, "wayland" and "x11" for a program that only
 * speaks one of them. */
struct TerminalProgram
{
    const char * name;
    const char * const leadingArgs[3];
    const char * backend;
};

/* The terminals in the order they are offered, for the unit tests and for
 * the documentation that lists them. */
const TerminalProgram * KnownTerminalPrograms(size_t * count);

/* The terminal program to start, and the option that gives it a command. */
struct TerminalChoice
{
    TerminalChoice() : viaXWayland(false) {}

    std::string program;
    std::vector<std::string> leadingArgs;
    /* The chosen program is an X11 one and the session is Wayland, so the
     * window is served by XWayland: it works, but it is not scaled by the
     * compositor and looks blurry on a high-resolution display. */
    bool viaXWayland;
};

/*
 * The first program of KnownTerminalPrograms() that is installed and can
 * show a window in 'session'; 'installed' holds the names found on PATH.
 * An X11 terminal in a Wayland session is kept as a fallback - XWayland
 * makes it work, which is why viaXWayland is reported rather than the
 * program refused - while a Wayland-only terminal is refused in an X11
 * session, because it would exit without a window and without a message the
 * user would see. The program is empty when the session can show no window
 * at all or when nothing installed fits it.
 */
TerminalChoice ChooseTerminalProgram(const DesktopSession & session,
    const std::vector<std::string> & installed);

/* Opens an interactive terminal on the given server: the system ssh in a
 * desktop terminal emulator (the terminal from LINSCP_TERMINAL,
 * otherwise the first installed one that this display session can show a
 * window in). Returns false with 'error' set when nothing could be started.
 * When 'note' is non-NULL it receives a message to tell the user about the
 * choice that was made - that the window is an XWayland one, say - which is
 * not a failure and not worth refusing. */
bool LaunchTerminalForServer(const std::string & userName,
    const std::string & hostName, int portNumber,
    const std::string & privateKeyFile, std::string & error,
    std::string * note = NULL);

} // namespace linscp

#endif /* LINSCP_PLATFORM_H */
