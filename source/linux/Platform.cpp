#include "Platform.h"

#include "LocalFs.h"

#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>

#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <chrono>
#include <thread>

namespace linscp {

namespace {

std::string EnvironmentVariable(const char * name)
{
    const char * value = getenv(name);
    return value != NULL ? std::string(value) : std::string();
}


} // namespace

void InitConsole()
{
}

bool StdInIsTerminal()
{
    return isatty(STDIN_FILENO) != 0;
}

bool StdOutIsTerminal()
{
    return isatty(STDOUT_FILENO) != 0;
}

EchoOff::EchoOff() : mActive(false), mFd(-1), mSaved(NULL)
{
    if (isatty(STDIN_FILENO))
    {
        struct termios * saved = new struct termios;
        if (tcgetattr(STDIN_FILENO, saved) == 0)
        {
            struct termios muted = *saved;
            muted.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            if (tcsetattr(STDIN_FILENO, TCSANOW, &muted) == 0)
            {
                mFd = STDIN_FILENO;
                mSaved = saved;
                mActive = true;
            }
        }
        if (!mActive)
        {
            delete saved;
        }
    }
}

EchoOff::~EchoOff()
{
    if (mActive && mSaved != NULL)
    {
        tcsetattr(mFd, TCSANOW, static_cast<struct termios *>(mSaved));
        delete static_cast<struct termios *>(mSaved);
    }
}

bool LocalTime(std::time_t value, std::tm & result)
{
    return localtime_r(&value, &result) != NULL;
}

std::string HomeDirectory()
{
    std::string home = EnvironmentVariable("HOME");
    if (!home.empty())
    {
        return home;
    }
    struct passwd pwd = {};
    struct passwd * result = NULL;
    char buffer[4096];
    if (getpwuid_r(getuid(), &pwd, buffer, sizeof(buffer), &result) == 0 &&
        result != NULL && pwd.pw_dir != NULL)
    {
        return std::string(pwd.pw_dir);
    }
    return std::string();
}

std::string ConfigDirectory()
{
    std::string overrideDir = EnvironmentVariable("LINSCP_CONFIG_DIR");
    if (!overrideDir.empty())
    {
        return overrideDir;
    }
    std::string xdg = EnvironmentVariable("XDG_CONFIG_HOME");
    if (!xdg.empty())
    {
        return xdg + "/LinSCP";
    }
    std::string home = HomeDirectory();
    if (!home.empty())
    {
        return home + "/.config/LinSCP";
    }
    return std::string();
}

std::string CurrentUserName()
{
    std::string user = EnvironmentVariable("USER");
    if (!user.empty())
    {
        return user;
    }
    user = EnvironmentVariable("LOGNAME");
    if (!user.empty())
    {
        return user;
    }
    struct passwd pwd = {};
    struct passwd * result = NULL;
    char buffer[4096];
    if (getpwuid_r(getuid(), &pwd, buffer, sizeof(buffer), &result) == 0 &&
        result != NULL && pwd.pw_name != NULL)
    {
        return std::string(pwd.pw_name);
    }
    return std::string();
}

bool SetFileTimes(const std::string & path, unsigned long atime,
    unsigned long mtime)
{
    struct timeval values[2];
    values[0].tv_sec = static_cast<time_t>(atime);
    values[0].tv_usec = 0;
    values[1].tv_sec = static_cast<time_t>(mtime);
    values[1].tv_usec = 0;
    return utimes(path.c_str(), values) == 0;
}

std::string TempDirectory()
{
    const char * candidates[] = { "TMPDIR", "TEMP", "TMP" };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
    {
        std::string value = EnvironmentVariable(candidates[i]);
        if (!value.empty())
        {
            while (value.size() > 1 && value[value.size() - 1] == '/')
            {
                value.erase(value.size() - 1);
            }
            return value;
        }
    }
    return "/tmp";
}

bool CreatePrivateDirectory(const std::string & path, std::string & error)
{
    /* The parents of these directories are the user's own configuration
     * or temporary directory, which other users cannot reach; only the
     * leaf is restricted explicitly. */
    if (!CreateLocalDirectoryRecursive(path, error))
    {
        return false;
    }
    chmod(path.c_str(), 0700);
    return true;
}

bool RestrictFileToUser(const std::string & path)
{
    return chmod(path.c_str(), 0600) == 0;
}

void SleepMilliseconds(unsigned milliseconds)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

namespace {

volatile sig_atomic_t gInterrupted = 0;

void InterruptHandler(int)
{
    gInterrupted = 1;
}

} // namespace

void InstallInterruptHandler()
{
    static bool installed = false;
    if (installed)
    {
        return;
    }
    installed = true;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = InterruptHandler;
    sigaction(SIGINT, &action, NULL);
}

bool Interrupted()
{
    return gInterrupted != 0;
}

void ClearInterrupt()
{
    gInterrupted = 0;
}

int RunInteractive(const std::vector<std::string> & args, std::string & error)
{
    if (args.empty())
    {
        error = "No program to run.";
        return -1;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0)
    {
        error = std::string("Cannot start '") + args[0] + "': " + strerror(errno);
        return -1;
    }
    if (pid == 0)
    {
        std::vector<char *> argv;
        argv.reserve(args.size() + 1);
        for (size_t i = 0; i < args.size(); i++)
        {
            argv.push_back(const_cast<char *>(args[i].c_str()));
        }
        argv.push_back(NULL);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno != EINTR)
        {
            error = std::string("Cannot wait for '") + args[0] + "': " + strerror(errno);
            return -1;
        }
    }
    if (WIFEXITED(status))
    {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status))
    {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

int RunCaptureWithOutput(const std::vector<std::string> & args,
    std::string & out, std::string & err, RunCaptureOutputFn output,
    void * ctx)
{
    out.clear();
    err.clear();
    if (args.empty() || args[0].empty())
    {
        err = "No command to run.";
        return -1;
    }

    int outPipe[2];
    int errPipe[2];
    if (pipe(outPipe) != 0)
    {
        err = std::string("Failed to create stdout pipe: ") + strerror(errno);
        return -1;
    }
    if (pipe(errPipe) != 0)
    {
        close(outPipe[0]);
        close(outPipe[1]);
        err = std::string("Failed to create stderr pipe: ") + strerror(errno);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(outPipe[0]);
        close(outPipe[1]);
        close(errPipe[0]);
        close(errPipe[1]);
        err = std::string("Failed to fork: ") + strerror(errno);
        return -1;
    }

    if (pid == 0)
    {
        close(outPipe[0]);
        close(errPipe[0]);
        if (dup2(outPipe[1], STDOUT_FILENO) < 0 ||
            dup2(errPipe[1], STDERR_FILENO) < 0)
        {
            _exit(127);
        }
        close(outPipe[1]);
        close(errPipe[1]);

        std::vector<char *> argv;
        argv.reserve(args.size() + 1);
        for (size_t i = 0; i < args.size(); i++)
        {
            argv.push_back(const_cast<char *>(args[i].c_str()));
        }
        argv.push_back(NULL);
        execvp(argv[0], argv.data());
        _exit(127);
    }

    close(outPipe[1]);
    close(errPipe[1]);

    /* Drain both pipes with poll() so the child never blocks on a full
     * pipe while we are reading the other one. */
    struct pollfd fds[2];
    fds[0].fd = outPipe[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = errPipe[0];
    fds[1].events = POLLIN;
    fds[1].revents = 0;
    int openCount = 2;
    char buffer[4096];
    while (openCount > 0)
    {
        int ready = poll(fds, 2, -1);
        if (ready < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        for (int i = 0; i < 2; i++)
        {
            if (fds[i].fd < 0)
            {
                continue;
            }
            if ((fds[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0)
            {
                ssize_t bytesRead = read(fds[i].fd, buffer, sizeof(buffer));
                if (bytesRead > 0)
                {
                    if (output != NULL)
                    {
                        output(buffer, static_cast<size_t>(bytesRead), i == 1, ctx);
                    }
                    (i == 0 ? out : err).append(buffer,
                        static_cast<size_t>(bytesRead));
                }
                else
                {
                    close(fds[i].fd);
                    fds[i].fd = -1;
                    openCount--;
                }
            }
            fds[i].revents = 0;
        }
    }
    if (fds[0].fd >= 0)
    {
        close(fds[0].fd);
    }
    if (fds[1].fd >= 0)
    {
        close(fds[1].fd);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno != EINTR)
        {
            break;
        }
    }
    if (WIFEXITED(status))
    {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status))
    {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

int RunCapture(const std::vector<std::string> & args, std::string & out,
    std::string & err)
{
    return RunCaptureWithOutput(args, out, err, NULL, NULL);
}

std::string FindExecutableOnPath(const std::string & name)
{
    if (name.empty())
    {
        return std::string();
    }
    if (name.find('/') != std::string::npos)
    {
        return access(name.c_str(), X_OK) == 0 ? name : std::string();
    }
    const char * pathEnv = getenv("PATH");
    if (pathEnv == NULL)
    {
        return std::string();
    }
    std::string path = pathEnv;
    size_t start = 0;
    while (start <= path.size())
    {
        size_t colon = path.find(':', start);
        std::string dir = path.substr(start,
            colon == std::string::npos ? colon : colon - start);
        if (dir.empty())
        {
            dir = ".";
        }
        std::string candidate = dir + "/" + name;
        if (access(candidate.c_str(), X_OK) == 0)
        {
            return candidate;
        }
        if (colon == std::string::npos)
        {
            break;
        }
        start = colon + 1;
    }
    return std::string();
}

std::string ExecutableDirectory()
{
    char buffer[4096];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len <= 0)
    {
        return std::string();
    }
    buffer[len] = '\0';
    std::string full(buffer, static_cast<size_t>(len));
    std::string::size_type slash = full.find_last_of('/');
    return slash == std::string::npos ? std::string() : full.substr(0, slash);
}

bool LaunchGuiApplication(std::string & error)
{
    error.clear();
    /* A CMake install may use any prefix, and a developer can run a build
     * from its tree. Launch the GUI next to this executable before looking
     * on PATH; /usr/bin must not win over the version being run. */
    const std::string directory = ExecutableDirectory();
    const std::string beside = directory.empty() ? std::string() :
        directory + "/linscp-gui";
    /* In an uninstalled source tree the Makefile binary is in
     * source/linux/build and the CMake binary is in build/. Use that tree's
     * launcher instead of a possibly older package on PATH. */
    const std::string makeTree = directory + "/../../gui/linscp-gui";
    const std::string cmakeTree = directory + "/../source/gui/linscp-gui";
    std::string guiBin;
    if (!beside.empty() && access(beside.c_str(), X_OK) == 0)
        guiBin = beside;
    else if (!directory.empty() && access(makeTree.c_str(), X_OK) == 0)
        guiBin = makeTree;
    else if (!directory.empty() && access(cmakeTree.c_str(), X_OK) == 0)
        guiBin = cmakeTree;
    else
        guiBin = FindExecutableOnPath("linscp-gui");
    if (guiBin.empty())
    {
        guiBin = "/usr/bin/linscp-gui";
    }
    execl(guiBin.c_str(), guiBin.c_str(), static_cast<char *>(NULL));
    error = std::string("Failed to launch LinSCP GUI '") + guiBin +
        "': " + strerror(errno);
    return false;
}

/*
 * The date columns of the protocol backends: curl's 'Last-Modified'
 * header and the date column of an 'ls -l' listing. Both live here so
 * that the unit tests can reach them without the PuTTY core.
 */

static int MonthFromName(const std::string & name)
{
    static const char * const months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    for (int i = 0; i < 12; i++)
    {
        if (name == months[i])
        {
            return i;
        }
    }
    return -1;
}

unsigned long ParseHttpDate(const std::string & text)
{
    /* 'Tue, 13 Oct 2026 05:21:00 GMT', as curl prints Last-Modified. */
    const char * start = strchr(text.c_str(), ',');
    start = start != NULL ? start + 1 : text.c_str();
    int day = 0;
    int year = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    char monthName[16] = {0};
    /* Width-limited: the header comes from the server, and an unbounded
     * %d on twenty digits is undefined behaviour rather than a refused
     * date. The ranges below turn a parsed-but-impossible date into one. */
    if (sscanf(start, " %2d %15s %4d %2d:%2d:%2d", &day, monthName, &year, &hour,
            &minute, &second) != 6)
    {
        return 0;
    }
    if (year < 1970 || year > 9999 || hour > 23 || minute > 59 || second > 60)
    {
        return 0;
    }
    const int month = MonthFromName(monthName);
    if (month < 0 || day <= 0 || day > 31)
    {
        return 0;
    }
    struct tm value = {};
    value.tm_year = year - 1900;
    value.tm_mon = month;
    value.tm_mday = day;
    value.tm_hour = hour;
    value.tm_min = minute;
    value.tm_sec = second;
    /* The header is in GMT. */
    const std::time_t stamp = timegm(&value);
    return stamp > 0 ? static_cast<unsigned long>(stamp) : 0;
}

unsigned long ParseListingDate(const std::string & monthName,
    const std::string & dayText, const std::string & timeOrYear)
{
    /*
     * 'Oct 13 05:21' for an entry from the last six months, 'Oct 13  2026'
     * for an older one. The listing uses the server's local time, which is
     * the same clock the client displays timestamps in.
     */
    const int month = MonthFromName(monthName);
    int day = 0;
    if (month < 0 || dayText.empty())
    {
        return 0;
    }
    try
    {
        day = std::stoi(dayText);
    }
    catch (...)
    {
        return 0;
    }
    if (day <= 0 || day > 31)
    {
        return 0;
    }

    const bool hasClockTime = timeOrYear.find(':') != std::string::npos;
    int hour = 0;
    int minute = 0;
    int year = 0;
    if (hasClockTime)
    {
        const std::string::size_type colon = timeOrYear.find(':');
        try
        {
            hour = std::stoi(timeOrYear.substr(0, colon));
            minute = std::stoi(timeOrYear.substr(colon + 1));
        }
        catch (...)
        {
            return 0;
        }
        if (hour < 0 || hour > 23 || minute < 0 || minute > 59)
        {
            return 0;
        }
        std::time_t now = std::time(NULL);
        struct tm nowParts;
        if (!LocalTime(now, nowParts))
        {
            return 0;
        }
        year = nowParts.tm_year + 1900;
    }
    else
    {
        try
        {
            year = std::stoi(timeOrYear);
        }
        catch (...)
        {
            return 0;
        }
    }
    if (year < 1970 || year > 9999)
    {
        return 0;
    }

    struct tm value = {};
    value.tm_year = year - 1900;
    value.tm_mon = month;
    value.tm_mday = day;
    value.tm_hour = hour;
    value.tm_min = minute;
    value.tm_sec = 0;
    value.tm_isdst = -1;
    std::time_t stamp = std::mktime(&value);
    if (hasClockTime)
    {
        /* No year in the listing: a date more than a day ahead of the
         * clock must belong to the previous year. */
        const std::time_t limit = std::time(NULL) + 24 * 60 * 60;
        if (stamp > limit)
        {
            value.tm_year--;
            stamp = std::mktime(&value);
        }
    }
    return stamp > 0 ? static_cast<unsigned long>(stamp) : 0;
}


/* ----------------------------------------------------------------------
 * An interactive terminal on the connected server
 *
 * WinSCP's "Open Terminal" opens the desktop's terminal program on the
 * server that the session is using. The console client cannot make its
 * own terminal window, so it hands the same job to the system ssh client
 * in a terminal emulator.
 */

std::vector<std::string> BuildSshArguments(const std::string & userName,
    const std::string & hostName, int portNumber,
    const std::string & privateKeyFile)
{
    std::vector<std::string> args;
    /* The system ssh client reads OpenSSH key files but cannot read the
     * PuTTY .ppk files that this client's own SSH core uses; a .ppk is
     * therefore left to the agent (the terminal then asks for a password
     * when there is no usable agent key). */
    std::string keyExtension = privateKeyFile.size() >= 4 ?
        privateKeyFile.substr(privateKeyFile.size() - 4) : std::string();
    for (size_t i = 0; i < keyExtension.size(); i++)
    {
        keyExtension[i] = static_cast<char>(tolower(static_cast<unsigned char>(keyExtension[i])));
    }
    if (!privateKeyFile.empty() && keyExtension != ".ppk")
    {
        args.push_back("-i");
        args.push_back(privateKeyFile);
    }
    if (portNumber > 0 && portNumber != 22)
    {
        args.push_back("-p");
        args.push_back(std::to_string(portNumber));
    }
    /* A terminal is wanted even though the client's own stdin is not one
     * (in the GUI the client runs without a console). */
    args.push_back("-t");
    args.push_back(userName.empty() ? hostName : userName + "@" + hostName);
    return args;
}


namespace {

struct TerminalProgram
{
    const char * name;
    const char * leadingArgs[3];
};

/*
 * The terminal emulators of the common desktops, with the option that
 * makes them run a command instead of a shell. Some of them take the
 * command after '--', some after '-e' or '-x', and kitty/foot take it
 * directly.
 */
const TerminalProgram kTerminalPrograms[] = {
    {"x-terminal-emulator", {"-e", NULL}},
    {"gnome-terminal", {"--", NULL}},
    {"konsole", {"-e", NULL}},
    {"xfce4-terminal", {"-x", NULL}},
    {"mate-terminal", {"-x", NULL}},
    {"lxterminal", {"-e", NULL}},
    {"terminator", {"-x", NULL}},
    {"alacritty", {"-e", NULL}},
    {"kitty", {NULL}},
    {"foot", {NULL}},
    {"wezterm", {"start", "--", NULL}},
    {"urxvt", {"-e", NULL}},
    {"xterm", {"-e", NULL}},
};

std::vector<std::string> SplitWhitespace(const std::string & text)
{
    std::vector<std::string> words;
    std::string word;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] == ' ' || text[i] == '\t')
        {
            if (!word.empty())
            {
                words.push_back(word);
                word.clear();
            }
            continue;
        }
        word += text[i];
    }
    if (!word.empty())
    {
        words.push_back(word);
    }
    return words;
}

std::string SshHint(const std::string & userName, const std::string & hostName,
    int portNumber)
{
    std::string hint = " Run 'ssh";
    if (portNumber > 0 && portNumber != 22)
    {
        hint += " -p " + std::to_string(portNumber);
    }
    hint += " " + (userName.empty() ? hostName : userName + "@" + hostName);
    hint += "' in a terminal of your own instead.";
    return hint;
}

} // namespace

bool LaunchTerminalForServer(const std::string & userName,
    const std::string & hostName, int portNumber,
    const std::string & privateKeyFile, std::string & error)
{
    error.clear();

    std::string program;
    std::vector<std::string> leading;
    const std::string overrideProgram = EnvironmentVariable("LINSCP_TERMINAL");
    if (!overrideProgram.empty())
    {
        /* '<program> [args]', e.g. 'xterm -e' or 'foot'. */
        const std::vector<std::string> words = SplitWhitespace(overrideProgram);
        program = words[0];
        leading.assign(words.begin() + 1, words.end());
    }
    else
    {
        if (EnvironmentVariable("DISPLAY").empty() &&
            EnvironmentVariable("WAYLAND_DISPLAY").empty())
        {
            error = "No graphical session was found (DISPLAY and WAYLAND_DISPLAY "
                "are not set), so no terminal window can be opened.";
            error += SshHint(userName, hostName, portNumber);
            return false;
        }
        for (size_t i = 0; i < sizeof(kTerminalPrograms) / sizeof(kTerminalPrograms[0]); i++)
        {
            const std::string found = FindExecutableOnPath(kTerminalPrograms[i].name);
            if (found.empty())
            {
                continue;
            }
            program = found;
            for (int n = 0; n < 3 && kTerminalPrograms[i].leadingArgs[n] != NULL; n++)
            {
                leading.push_back(kTerminalPrograms[i].leadingArgs[n]);
            }
            break;
        }
        if (program.empty())
        {
            error = "None of the common desktop terminals is installed; set "
                "LINSCP_TERMINAL to the terminal program to use.";
            error += SshHint(userName, hostName, portNumber);
            return false;
        }
    }

    std::string ssh = FindExecutableOnPath("ssh");
    if (ssh.empty())
    {
        error = "The ssh client is not installed, so no terminal can be opened.";
        return false;
    }

    std::vector<std::string> command;
    command.push_back(program);
    command.insert(command.end(), leading.begin(), leading.end());
    command.push_back(ssh);
    const std::vector<std::string> sshArgs = BuildSshArguments(userName,
        hostName, portNumber, privateKeyFile);
    command.insert(command.end(), sshArgs.begin(), sshArgs.end());

    /*
     * Start the terminal without waiting for it (it outlives this
     * process), but report a failed exec: the write end of the pipe is
     * closed by the exec, and a child that cannot exec writes the reason
     * into it instead.
     */
    int statusPipe[2];
    if (pipe(statusPipe) != 0)
    {
        error = std::string("Failed to create the exec status pipe: ") + strerror(errno);
        return false;
    }
    const pid_t pid = fork();
    if (pid < 0)
    {
        close(statusPipe[0]);
        close(statusPipe[1]);
        error = std::string("Failed to fork: ") + strerror(errno);
        return false;
    }
    if (pid == 0)
    {
        /* Intermediate child: exit at once so the terminal is not a child
         * of this process (nobody would wait for it). */
        close(statusPipe[0]);
        const pid_t grandchild = fork();
        if (grandchild != 0)
        {
            _exit(grandchild < 0 ? 1 : 0);
        }
        (void)fcntl(statusPipe[1], F_SETFD, FD_CLOEXEC);
        std::vector<char *> argv;
        argv.reserve(command.size() + 1);
        for (size_t i = 0; i < command.size(); i++)
        {
            argv.push_back(const_cast<char *>(command[i].c_str()));
        }
        argv.push_back(NULL);
        execvp(argv[0], argv.data());
        const int saved = errno;
        (void)!write(statusPipe[1], &saved, sizeof(saved));
        _exit(127);
    }

    close(statusPipe[1]);
    int childStatus = 0;
    while (waitpid(pid, &childStatus, 0) < 0 && errno == EINTR)
    {
    }
    int execError = 0;
    const ssize_t got = read(statusPipe[0], &execError, sizeof(execError));
    close(statusPipe[0]);
    if (got == static_cast<ssize_t>(sizeof(execError)) && execError != 0)
    {
        error = "Failed to start '" + program + "': " + strerror(execError) + ".";
        error += SshHint(userName, hostName, portNumber);
        return false;
    }
    return true;
}

} // namespace linscp
