/*
 * Unit tests for the platform-neutral parts of the LinSCP front end:
 * command line splitting, path handling, file masks, the output
 * formatting helpers, site URL parsing and local file system access.
 *
 * Run them with 'make -C source/linux check'.
 *
 * The connection code is not covered here; it needs a server, and is
 * exercised end to end instead (see docs/debian.md).
 */

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <filesystem>
#include <map>
#include <sys/stat.h>
#include <libssh/libssh.h>

/* The GSSAPI-specific public helper is absent from libssh builds without
 * WITH_GSSAPI. Mirror the production weak probe to verify the build-time
 * capability, including in CI builds that do not provide Kerberos. */
#pragma weak ssh_gssapi_set_creds

#include "PathUtil.h"
#include "ScriptParams.h"
#include "LocalFs.h"
#include "Platform.h"
#include "Session.h"
#include "Script.h"
#include "Console.h"
#include "Texts.h"
#include "Editor.h"
#include "SessionStore.h"
#include "S3SigV4.h"
#include "SyncPlanner.h"
#include "ProtocolClient.h"
#include "SshTunnel.h"
#include "SftpClient.h"
#include "Editor.h"
#include "ScpClient.h"
#include "FtpClient.h"
#include "HashUtil.h"
#include "ListingParse.h"
#include "PpkKey.h"
#include "TextMode.h"
#include "TransferPresets.h"

namespace {

int gFailures = 0;
int gChecks = 0;

void ReportFailure(const char * file, int line, const std::string & what)
{
    gFailures++;
    fprintf(stderr, "%s:%d: %s\n", file, line, what.c_str());
}

#define CHECK_EQ(actual, expected)                                            \
    do {                                                                      \
        gChecks++;                                                            \
        const std::string got = (actual);                                     \
        const std::string want = (expected);                                  \
        if (got != want)                                                      \
        {                                                                     \
            ReportFailure(__FILE__, __LINE__, std::string("expected '") +     \
                want + "', got '" + got + "'");                               \
        }                                                                     \
    } while (false)

#define CHECK_TRUE(expr)                                                      \
    do {                                                                      \
        gChecks++;                                                            \
        if (!(expr))                                                          \
        {                                                                     \
            ReportFailure(__FILE__, __LINE__, "expected true: " #expr);       \
        }                                                                     \
    } while (false)

#define CHECK_FALSE(expr)                                                     \
    do {                                                                      \
        gChecks++;                                                            \
        if (expr)                                                             \
        {                                                                     \
            ReportFailure(__FILE__, __LINE__, "expected false: " #expr);      \
        }                                                                     \
    } while (false)

using namespace linscp;

void SetEnvVar(const char * name, const char * value)
{
    if (value != NULL)
    {
        setenv(name, value, 1);
    }
    else
    {
        unsetenv(name);
    }
}

std::string MakeTempDirectory()
{
    std::error_code ec;
    std::filesystem::path base = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return std::string();
    }
    for (int attempt = 0; attempt < 100; attempt++)
    {
        std::filesystem::path candidate = base /
            ("linscp-unittest-" + std::to_string(attempt) + "-" +
             std::to_string(static_cast<unsigned long>(time(NULL))));
        if (std::filesystem::create_directory(candidate, ec))
        {
            return candidate.string();
        }
        ec.clear();
    }
    return std::string();
}

bool RemoveDirectoryQuiet(const std::string & path)
{
    std::error_code ec;
    return std::filesystem::remove(std::filesystem::path(path), ec) && !ec;
}

std::string Words(const std::vector<std::string> & words)
{
    std::string result;
    for (size_t i = 0; i < words.size(); i++)
    {
        result += "[" + words[i] + "]";
    }
    return result;
}

void TestSplitCommandLine()
{
    CHECK_EQ(Words(SplitCommandLine("get a.txt b.txt")), "[get][a.txt][b.txt]");
    CHECK_EQ(Words(SplitCommandLine("   put   /tmp/a   .   ")), "[put][/tmp/a][.]");
    CHECK_EQ(Words(SplitCommandLine("")), "");
    CHECK_EQ(Words(SplitCommandLine("get 'two words.txt' dest")),
        "[get][two words.txt][dest]");
    CHECK_EQ(Words(SplitCommandLine("get \"two words.txt\" dest")),
        "[get][two words.txt][dest]");
    CHECK_EQ(Words(SplitCommandLine("get a\\ b.txt")), "[get][a b.txt]");
    /* Inside double quotes a backslash is literal unless it stands in
     * front of a double quote or of another backslash, as a POSIX shell
     * does it. A path carried over from a Windows client keeps its
     * separators this way. */
    CHECK_EQ(Words(SplitCommandLine("get \"C:\\Users\\me\\file.txt\"")),
        "[get][C:\\Users\\me\\file.txt]");
    CHECK_EQ(Words(SplitCommandLine("get \"a\\\\b.txt\"")), "[get][a\\b.txt]");
    CHECK_EQ(Words(SplitCommandLine("get \"say \\\"hi\\\"\"")),
        "[get][say \"hi\"]");
    /* A single-quoted word is literal, backslash included. */
    CHECK_EQ(Words(SplitCommandLine("get 'C:\\Users\\me'")), "[get][C:\\Users\\me]");
    /* An unterminated quote still yields the word read so far. */
    CHECK_EQ(Words(SplitCommandLine("get 'unterminated")), "[get][unterminated]");
    /* An empty quoted argument is a word of its own. */
    CHECK_EQ(Words(SplitCommandLine("get \"\" x")), "[get][][x]");
}

void TestSplitCommands()
{
    CHECK_EQ(Words(SplitCommands("pwd")), "[pwd]");
    CHECK_EQ(Words(SplitCommands("open sftp://h/ ; pwd ; exit")),
        "[open sftp://h/ ][ pwd ][ exit]");
    CHECK_EQ(Words(SplitCommands("cd /a;cd /b")), "[cd /a][cd /b]");
    /* A trailing ';' does not produce an empty command. */
    CHECK_EQ(Words(SplitCommands("pwd;")), "[pwd]");
    CHECK_EQ(Words(SplitCommands("")), "");
    /* A ';' inside quotes is part of the argument. */
    CHECK_EQ(Words(SplitCommands("get 'a;b.txt' .")), "[get 'a;b.txt' .]");
    CHECK_EQ(Words(SplitCommands("get \"a;b.txt\" .")), "[get \"a;b.txt\" .]");
}

void TestRemotePaths()
{
    CHECK_TRUE(IsRemoteAbsolutePath("/tmp"));
    CHECK_TRUE(IsRemoteAbsolutePath("/"));
    CHECK_FALSE(IsRemoteAbsolutePath("tmp"));
    CHECK_FALSE(IsRemoteAbsolutePath(""));

    CHECK_EQ(RemoteDirName("/tmp/file.txt"), "/tmp");
    CHECK_EQ(RemoteDirName("/file.txt"), "/");
    CHECK_EQ(RemoteDirName("file.txt"), "");
    CHECK_EQ(RemoteFileName("/tmp/file.txt"), "file.txt");
    CHECK_EQ(RemoteFileName("file.txt"), "file.txt");
    CHECK_EQ(RemoteFileName("/tmp/"), "");

    CHECK_EQ(JoinRemotePath("/tmp", "file.txt"), "/tmp/file.txt");
    CHECK_EQ(JoinRemotePath("/tmp/", "file.txt"), "/tmp/file.txt");
    CHECK_EQ(JoinRemotePath("/tmp", "/etc/passwd"), "/etc/passwd");
    CHECK_EQ(JoinRemotePath("/tmp", ""), "/tmp");
    CHECK_EQ(JoinRemotePath("", "file.txt"), "file.txt");

    CHECK_EQ(ResolveRemotePath("/home/user", "sub"), "/home/user/sub");
    CHECK_EQ(ResolveRemotePath("/home/user", "./sub/../other"), "/home/user/other");
    CHECK_EQ(ResolveRemotePath("/home/user", ".."), "/home");
    CHECK_EQ(ResolveRemotePath("/home", ".."), "/");
    CHECK_EQ(ResolveRemotePath("/", ".."), "/");
    CHECK_EQ(ResolveRemotePath("/home/user", "/etc"), "/etc");
    CHECK_EQ(ResolveRemotePath("/home/user", "/"), "/");
    CHECK_EQ(ResolveRemotePath("", "sub"), "/sub");
    /* A trailing slash is not part of the resolved name. */
    CHECK_EQ(ResolveRemotePath("/home/user", "sub/"), "/home/user/sub");
}

void TestLocalPaths()
{
    std::string homeDir = HomeDirectory();
    if (!homeDir.empty())
    {
        CHECK_EQ(ExpandTilde("~"), homeDir);
        CHECK_EQ(ExpandTilde("~/docs"), JoinLocalPath(homeDir, "docs"));
        /* '~user' is deliberately not supported. */
        CHECK_EQ(ExpandTilde("~user"), "~user");
    }
    CHECK_EQ(ExpandTilde(""), "");
    CHECK_EQ(ExpandTilde("/tmp"), "/tmp");
    const char * oldHomeValue = getenv("HOME");
    const bool hadHome = oldHomeValue != NULL;
    const std::string oldHome = hadHome ? oldHomeValue : "";
    SetEnvVar("HOME", "/");
    CHECK_EQ(ExpandTilde("~/docs"), "/docs");
    SetEnvVar("HOME", hadHome ? oldHome.c_str() : NULL);

    CHECK_EQ(LocalDirName("/tmp/file.txt"), "/tmp");
    CHECK_EQ(LocalDirName("file.txt"), ".");
    CHECK_EQ(LocalFileName("/tmp/file.txt"), "file.txt");
    CHECK_EQ(JoinLocalPath("/tmp", "a"), "/tmp/a");
    CHECK_EQ(JoinLocalPath("/tmp/", "a"), "/tmp/a");
    CHECK_EQ(JoinLocalPath("/tmp", "/etc/passwd"), "/etc/passwd");

    CHECK_EQ(ResolveLocalPath("/home/user", "sub"), "/home/user/sub");
    CHECK_EQ(ResolveLocalPath("/home/user", "/etc"), "/etc");
    CHECK_EQ(ResolveLocalPath("/home/user", "."), "/home/user");
    if (!homeDir.empty())
    {
        CHECK_EQ(ResolveLocalPath("/tmp", "~/docs"), JoinLocalPath(homeDir, "docs"));
    }
    CHECK_FALSE(IsLocalAbsolutePath("tmp/file"));
    CHECK_TRUE(IsLocalAbsolutePath("/tmp"));
}

void TestMasks()
{
    CHECK_TRUE(HasWildcard("*.txt"));
    CHECK_TRUE(HasWildcard("a?.txt"));
    CHECK_FALSE(HasWildcard("a.txt"));
    CHECK_FALSE(HasWildcard(""));

    CHECK_TRUE(MatchesMask("*.txt", "a.txt"));
    CHECK_TRUE(MatchesMask("*.txt", ".txt"));
    CHECK_FALSE(MatchesMask("*.txt", "a.tar"));
    CHECK_TRUE(MatchesMask("a?c", "abc"));
    CHECK_FALSE(MatchesMask("a?c", "ac"));
    CHECK_FALSE(MatchesMask("a?c", "abbc"));
    CHECK_TRUE(MatchesMask("*", "anything"));
    CHECK_TRUE(MatchesMask("*", ""));
    CHECK_TRUE(MatchesMask("*.tar.gz", "linscp-1.0.tar.gz"));
    CHECK_TRUE(MatchesMask("a*b*c", "axxbyyc"));
    CHECK_FALSE(MatchesMask("a*b*c", "axxbyy"));
    /* A mask without wildcards matches exactly one name. */
    CHECK_TRUE(MatchesMask("file.txt", "file.txt"));
    CHECK_FALSE(MatchesMask("file.txt", "file.txtx"));
    CHECK_FALSE(MatchesMask("", "a"));
    CHECK_TRUE(MatchesMask("", ""));
}

void TestMaskCase()
{
    CHECK_FALSE(MatchesMask("*.TXT", "a.txt"));
}

struct StreamCapture
{
    std::string stdoutText;
    std::string stderrText;
    unsigned chunks;
    StreamCapture() : chunks(0) {}
};

void CaptureChildOutput(const void * data, size_t len, bool fromStderr, void * ctx)
{
    StreamCapture & capture = *static_cast<StreamCapture *>(ctx);
    capture.chunks++;
    (fromStderr ? capture.stderrText : capture.stdoutText).append(
        static_cast<const char *>(data), len);
}

void TestPlatformServices()
{
    /* Process capture returns the exit code and both streams. */
    std::string out;
    std::string err;
    std::vector<std::string> args;
    args.push_back("echo");
    args.push_back("hello-posix");
    CHECK_TRUE(RunCapture(args, out, err) == 0);
    CHECK_TRUE(out.find("hello-posix") != std::string::npos);

    /* The streaming form is what curl progress uses: stdout and stderr
     * remain captured while chunks are delivered before the child exits. */
    std::vector<std::string> streamArgs;
    streamArgs.push_back("sh");
    streamArgs.push_back("-c");
    streamArgs.push_back("printf stdout; printf stderr >&2");
    StreamCapture capture;
    CHECK_TRUE(RunCaptureWithOutput(streamArgs, out, err,
        CaptureChildOutput, &capture) == 0);
    CHECK_TRUE(capture.chunks >= 2);
    CHECK_EQ(capture.stdoutText, "stdout");
    CHECK_EQ(capture.stderrText, "stderr");
    CHECK_EQ(out, "stdout");
    CHECK_EQ(err, "stderr");

    /* A missing program is a start failure, not a crash. */
    std::vector<std::string> missing;
    missing.push_back("linscp-no-such-program-xyz");
    CHECK_TRUE(RunCapture(missing, out, err) == -1 || !err.empty() || out.empty());

    CHECK_TRUE(!HomeDirectory().empty() || !ConfigDirectory().empty());

    /* The interrupt record a watching command stops on: it survives the
     * signal, and the caller that goes on to run more commands in the same
     * process can forget it, or the next one stops before it starts. */
    InstallInterruptHandler();
    CHECK_FALSE(Interrupted());
    CHECK_TRUE(raise(SIGINT) == 0);
    CHECK_TRUE(Interrupted());
    ClearInterrupt();
    CHECK_FALSE(Interrupted());
}

struct TransferProgressCapture
{
    unsigned callbacks;
    unsigned long long last;
    unsigned long long total;
    TransferProgressCapture() : callbacks(0), last(0), total(0) {}
};

void CaptureTransferProgress(unsigned long long transferred,
    unsigned long long total, void * ctx)
{
    TransferProgressCapture & capture =
        *static_cast<TransferProgressCapture *>(ctx);
    capture.callbacks++;
    capture.last = transferred;
    capture.total = total;
}

void TestCurlProgress()
{
    /* This is a local file:// transfer, so the test exercises curl's Linux
     * child-process progress path without depending on an FTP/WebDAV server.
     * curl is a runtime dependency rather than a C++ build dependency; keep
     * the platform unit suite usable on a minimal compiler-only host. */
    if (FindExecutableOnPath("curl").empty())
    {
        return;
    }
    const std::string directory = MakeTempDirectory();
    CHECK_TRUE(!directory.empty());
    if (directory.empty())
    {
        return;
    }
    const std::string source = directory + "/progress-source.bin";
    const std::string target = directory + "/progress-target.bin";
    const std::string uploadTarget = directory + "/progress-upload.bin";
    FILE * file = fopen(source.c_str(), "wb");
    CHECK_TRUE(file != NULL);
    if (file == NULL)
    {
        RemoveDirectoryQuiet(directory);
        return;
    }
    std::vector<unsigned char> bytes(128 * 1024, 0x5a);
    CHECK_EQ(std::to_string(fwrite(bytes.data(), 1, bytes.size(), file)),
        std::to_string(bytes.size()));
    fclose(file);

    std::vector<std::string> args;
    args.push_back(FindExecutableOnPath("curl"));
    args.push_back("-S");
    args.push_back("--progress-meter");
    args.push_back("-o");
    args.push_back(target);
    args.push_back("file://" + source);
    std::string out;
    std::string error;
    TransferProgressCapture capture;
    CHECK_TRUE(RunCurlCaptureWithProgress(args, out, error,
        CaptureTransferProgress, &capture, false) == 0);
    CHECK_TRUE(capture.callbacks > 0);
    CHECK_TRUE(capture.total > 0);
    CHECK_TRUE(capture.last > 0);
    CHECK_EQ(std::to_string(StatLocal(target).size),
        std::to_string(bytes.size()));

    /* Uploads use the other curl meter column; file:// keeps this test
     * independent of a network service while still exercising that parser
     * branch and the callback's total-byte contract. */
    std::vector<std::string> uploadArgs;
    uploadArgs.push_back(FindExecutableOnPath("curl"));
    uploadArgs.push_back("-S");
    uploadArgs.push_back("--progress-meter");
    uploadArgs.push_back("-T");
    uploadArgs.push_back(source);
    uploadArgs.push_back("file://" + uploadTarget);
    TransferProgressCapture uploadCapture;
    CHECK_TRUE(RunCurlCaptureWithProgress(uploadArgs, out, error,
        CaptureTransferProgress, &uploadCapture, true) == 0);
    CHECK_TRUE(uploadCapture.callbacks > 0);
    CHECK_TRUE(uploadCapture.total > 0);
    CHECK_TRUE(uploadCapture.last > 0);
    CHECK_EQ(std::to_string(StatLocal(uploadTarget).size),
        std::to_string(bytes.size()));

    remove(source.c_str());
    remove(target.c_str());
    remove(uploadTarget.c_str());
    CHECK_TRUE(RemoveDirectoryQuiet(directory));
}

void TestDateParsing()
{
    /*
     * The listing date is read in local time. Pin the zone so that the
     * expected values do not depend on where the tests run.
     */
    setenv("TZ", "UTC", 1);
    tzset();

    /* curl prints Last-Modified in GMT. */
    CHECK_EQ(std::to_string(ParseHttpDate("Tue, 13 Oct 2026 05:21:00 GMT")),
        "1791868860");
    CHECK_EQ(std::to_string(ParseHttpDate("Sun, 03 Mar 2019 12:00:00 GMT")),
        "1551614400");
    CHECK_EQ(std::to_string(ParseHttpDate("")), "0");
    CHECK_EQ(std::to_string(ParseHttpDate("not a date")), "0");

    /* An 'ls -l' date column: a year for older entries, a clock time
     * otherwise. */
    CHECK_EQ(std::to_string(ParseListingDate("Mar", "3", "2019")), "1551571200");
    CHECK_EQ(std::to_string(ParseListingDate("Oct", "13", "2026")),
        "1791849600");
    CHECK_EQ(std::to_string(ParseListingDate("Mar", "3", "25:00")), "0");
    CHECK_EQ(std::to_string(ParseListingDate("Mar", "3", "12:60")), "0");
    CHECK_EQ(std::to_string(ParseListingDate("Xyz", "3", "2019")), "0");
    CHECK_EQ(std::to_string(ParseListingDate("Mar", "32", "2019")), "0");
    CHECK_EQ(std::to_string(ParseListingDate("Mar", "", "2019")), "0");
    const unsigned long thisYear = ParseListingDate("Jan", "1", "00:00");
    CHECK_TRUE(thisYear >= 1767225600UL);
}

/* The 'terminal' command hands the connection details to the system ssh
 * client; the argument list must not grow options that ssh does not
 * take, and a PPK-format key file must not be passed as -i. */
void TestTerminalCommandLine()
{
    const std::vector<std::string> plain = BuildSshArguments("user", "host", 22, "");
    CHECK_EQ(std::to_string(plain.size()), "2");
    CHECK_EQ(plain[0], "-t");
    CHECK_EQ(plain[1], "user@host");

    const std::vector<std::string> full = BuildSshArguments("user", "host", 2222,
        "/home/user/.ssh/id_ed25519");
    CHECK_EQ(std::to_string(full.size()), "6");
    CHECK_EQ(full[0], "-i");
    CHECK_EQ(full[1], "/home/user/.ssh/id_ed25519");
    CHECK_EQ(full[2], "-p");
    CHECK_EQ(full[3], "2222");
    CHECK_EQ(full[4], "-t");
    CHECK_EQ(full[5], "user@host");

    /* No user name: the client asks for one itself. */
    const std::vector<std::string> anonymous = BuildSshArguments("", "host", 22, "");
    CHECK_EQ(anonymous[1], "host");

    /* A PPK-format key file cannot be read by the ssh client. */
    const std::vector<std::string> ppk = BuildSshArguments("user", "host", 22,
        "/keys/private.PPK");
    CHECK_EQ(std::to_string(ppk.size()), "2");
    CHECK_EQ(ppk[0], "-t");
}

/* The display server the 'terminal' command looks for a window in. A
 * Wayland session is recognised by the compositor's socket rather than by a
 * variable, which a launcher or a service manager may not have forwarded,
 * and a terminal that cannot draw on this session must not be started at
 * all: an X11-only program has XWayland to fall back on, a Wayland-only one
 * has nothing and exits before it maps a window. */
namespace {

/* The paths the probe below claims exist, so that no test needs a
 * compositor - or the absence of one - to say what the session is. */
struct SocketPaths
{
    const char * paths[4];
};

bool ProbeSocket(const std::string & path, void * ctx)
{
    const SocketPaths * listed = static_cast<const SocketPaths *>(ctx);
    for (int i = 0; i < 4 && listed->paths[i] != NULL; i++)
    {
        if (path == listed->paths[i])
        {
            return true;
        }
    }
    return false;
}

std::map<std::string, std::string> DesktopEnvironment(const char * name,
    const char * value, const char * firstName = NULL,
    const char * firstValue = NULL)
{
    std::map<std::string, std::string> environment;
    if (firstName != NULL)
    {
        environment[firstName] = firstValue != NULL ? firstValue : "";
    }
    environment[name] = value != NULL ? value : "";
    return environment;
}

std::vector<std::string> Installed(const char * first,
    const char * second = NULL, const char * third = NULL)
{
    std::vector<std::string> installed;
    if (first != NULL) installed.push_back(first);
    if (second != NULL) installed.push_back(second);
    if (third != NULL) installed.push_back(third);
    return installed;
}

} // namespace

void TestDesktopSessionDetection()
{
    SocketPaths none = {{NULL, NULL, NULL, NULL}};
    SocketPaths sockets = {{"/run/user/1000/wayland-0",
        "/run/user/1000/wayland-server-1", "/tmp/wayland-socket", NULL}};

    /* X11 is taken from $DISPLAY without looking for anything: the variable
     * may name a forwarded display on another machine. */
    const DesktopSession x11 = DetectDesktopSession(
        DesktopEnvironment("DISPLAY", ":0"), ProbeSocket, &none);
    CHECK_TRUE(x11.x11);
    CHECK_FALSE(x11.wayland);

    /* A named Wayland socket that is there. */
    const DesktopSession wayland = DetectDesktopSession(
        DesktopEnvironment("WAYLAND_DISPLAY", "wayland-0",
            "XDG_RUNTIME_DIR", "/run/user/1000"), ProbeSocket, &sockets);
    CHECK_TRUE(wayland.wayland);
    CHECK_FALSE(wayland.x11);
    CHECK_TRUE(wayland.inferredWaylandDisplay.empty());

    /* The default name, found with no $WAYLAND_DISPLAY at all: a session
     * started by something that does not forward the variable still has a
     * compositor, and the child has to be told the name it found. */
    const DesktopSession inferred = DetectDesktopSession(
        DesktopEnvironment("XDG_RUNTIME_DIR", "/run/user/1000"),
        ProbeSocket, &sockets);
    CHECK_TRUE(inferred.wayland);
    CHECK_EQ(inferred.inferredWaylandDisplay, "wayland-0");
    CHECK_EQ(inferred.waylandSocketPath, "/run/user/1000/wayland-0");

    /* A named socket that is not in the runtime directory is no session;
     * a chosen compositor may run on another name. */
    const DesktopSession absent = DetectDesktopSession(
        DesktopEnvironment("WAYLAND_DISPLAY", "wayland-7",
            "XDG_RUNTIME_DIR", "/run/user/1000"), ProbeSocket, &sockets);
    CHECK_FALSE(absent.wayland);
    CHECK_FALSE(absent.waylandWithoutRuntimeDirectory);

    /* $WAYLAND_DISPLAY without $XDG_RUNTIME_DIR: no client can reach the
     * socket, and the message has to say which of the two is missing. */
    const DesktopSession orphaned = DetectDesktopSession(
        DesktopEnvironment("WAYLAND_DISPLAY", "wayland-0"), ProbeSocket, &none);
    CHECK_FALSE(orphaned.wayland);
    CHECK_TRUE(orphaned.waylandWithoutRuntimeDirectory);

    /* An absolute path in the variable, which libwayland accepts. */
    CHECK_TRUE(DetectDesktopSession(DesktopEnvironment("WAYLAND_DISPLAY",
        "/tmp/wayland-socket", "XDG_RUNTIME_DIR", "/run/user/1000"),
        ProbeSocket, &sockets).wayland);

    /* Neither variable: no window is possible anywhere. */
    const DesktopSession headless = DetectDesktopSession(
        std::map<std::string, std::string>(), ProbeSocket, &none);
    CHECK_FALSE(headless.x11);
    CHECK_FALSE(headless.wayland);

    /* Which terminal a session gets. */
    const std::vector<std::string> xWaylandAndNative = Installed("xterm",
        "foot", "gnome-terminal");
    CHECK_EQ(ChooseTerminalProgram(x11, xWaylandAndNative).program,
        "gnome-terminal");
    /* On Wayland the program that speaks the compositor's own protocol wins,
     * and where only X11 ones are installed the choice is still made -
     * reported as an XWayland fallback rather than refused. */
    const TerminalChoice onWayland = ChooseTerminalProgram(inferred,
        xWaylandAndNative);
    CHECK_EQ(onWayland.program, "gnome-terminal");
    CHECK_FALSE(onWayland.viaXWayland);
    const TerminalChoice fallback = ChooseTerminalProgram(inferred,
        Installed("xterm", "urxvt"));
    CHECK_EQ(fallback.program, "urxvt");
    CHECK_TRUE(fallback.viaXWayland);
    /* A Wayland-only terminal is refused under X11, in either session. */
    CHECK_TRUE(ChooseTerminalProgram(x11, Installed("foot")).program.empty());
    CHECK_EQ(ChooseTerminalProgram(inferred, Installed("foot")).program,
        "foot");
    /* No session at all: no program, however many are installed. */
    CHECK_TRUE(ChooseTerminalProgram(headless,
        xWaylandAndNative).program.empty());
    /* Debian's configured default is the X11 terminal alternative, so under
     * Wayland a program that speaks the compositor's own protocol is tried
     * first, and under X11 the configured default keeps its place. */
    const std::vector<std::string> distroDefault = Installed(
        "x-terminal-emulator", "konsole");
    CHECK_EQ(ChooseTerminalProgram(x11, distroDefault).program,
        "x-terminal-emulator");
    CHECK_EQ(ChooseTerminalProgram(inferred, distroDefault).program, "konsole");
    /* The option that makes the program run a command travels with the
     * choice: gnome-terminal wants '--', wezterm wants its own subcommand
     * before it, and foot wants nothing at all. */
    const TerminalChoice withSeparator = ChooseTerminalProgram(x11,
        Installed("gnome-terminal"));
    CHECK_EQ(std::to_string(withSeparator.leadingArgs.size()), "1");
    CHECK_EQ(withSeparator.leadingArgs[0], "--");
    CHECK_EQ(std::to_string(ChooseTerminalProgram(inferred,
        Installed("foot")).leadingArgs.size()), "0");
    const TerminalChoice wezterm = ChooseTerminalProgram(inferred,
        Installed("wezterm"));
    CHECK_EQ(wezterm.leadingArgs[0], "start");
    CHECK_EQ(wezterm.leadingArgs[1], "--");

    /* Every entry of the table names a backend a session can be matched
     * against, and each of the three kinds is present: a silent drop of one
     * of them would leave a whole display server without a terminal. */
    size_t count = 0;
    const TerminalProgram * programs = KnownTerminalPrograms(&count);
    CHECK_TRUE(count >= 13);
    bool sawWaylandOnly = false;
    bool sawX11Only = false;
    bool sawEither = false;
    for (size_t i = 0; i < count; i++)
    {
        CHECK_TRUE(programs[i].name[0] != '\0');
        const std::string backend = programs[i].backend != NULL ?
            programs[i].backend : "";
        CHECK_TRUE(backend.empty() || backend == "wayland" ||
            backend == "x11");
        sawWaylandOnly = sawWaylandOnly || backend == "wayland";
        sawX11Only = sawX11Only || backend == "x11";
        sawEither = sawEither || backend.empty();
    }
    CHECK_TRUE(sawWaylandOnly && sawX11Only && sawEither);
}

void TestFormatting()
{
    CHECK_EQ(FormatSize(0), "0");
    CHECK_EQ(FormatSize(12345), "12345");
    CHECK_EQ(FormatSize(1073741824ULL), "1073741824");

    CHECK_EQ(FormatPermissions(0040755), "drwxr-xr-x");
    CHECK_EQ(FormatPermissions(0100644), "-rw-r--r--");
    CHECK_EQ(FormatPermissions(0100600), "-rw-------");
    CHECK_EQ(FormatPermissions(0104755), "-rwsr-xr-x");
    CHECK_EQ(FormatPermissions(0100755), "-rwxr-xr-x");
    CHECK_EQ(FormatPermissions(0041755), "drwxr-xr-t");
    CHECK_EQ(FormatPermissions(0041754), "drwxr-xr-T");

    /* The type column is part of what a listing says: 'ls' and 'attr'
     * build their line here, and a symbolic link, a device or a socket
     * that printed as an ordinary file told the reader the entry could be
     * transferred as one. FormatPermissions() and the shared listing
     * parser are one implementation now, so they cannot disagree. */
    CHECK_EQ(FormatPermissions(0120777), "lrwxrwxrwx");
    CHECK_EQ(FormatPermissions(0140600), "srw-------");
    CHECK_EQ(FormatPermissions(0020660), "crw-rw----");
    CHECK_EQ(FormatPermissions(0060440), "br--r-----");
    CHECK_EQ(FormatPermissions(0010644), "prw-r--r--");
    CHECK_EQ(FormatPermissions(0120777), PermissionsString(0120777));
    CHECK_EQ(FormatPermissions(0104755), PermissionsString(0104755));
    CHECK_EQ(FormatPermissions(0040755), PermissionsString(0040755));

    /* The exact layout of a timestamp is locale and clock dependent, so
     * only check that it looks like 'ls -l' output. */
    const std::string when = FormatFileTime(1700000000UL);
    CHECK_TRUE(when.size() >= 11);
    CHECK_TRUE(when[3] == ' ');
    CHECK_EQ(FormatFileTime(0).substr(0, 3), "Jan");
}

void TestParseSiteUrl()
{
    SessionOptions options;
    std::string error;

    CHECK_TRUE(ParseSiteUrl("sftp://user:secret@example.com:2222/var/data",
        options, error));
    CHECK_EQ(options.hostName, "example.com");
    CHECK_TRUE(options.portNumber == 2222);
    CHECK_EQ(options.userName, "user");
    CHECK_EQ(options.password, "secret");
    CHECK_EQ(options.initialDirectory, "/var/data");

    /* Defaults. */
    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("sftp://example.com", options, error));
    CHECK_EQ(options.hostName, "example.com");
    CHECK_TRUE(options.portNumber == 22);
    CHECK_EQ(options.userName, "");
    CHECK_EQ(options.initialDirectory, "");

    /* Global command-line settings survive URLs that omit those fields. */
    options = SessionOptions();
    options.portNumber = 2200;
    options.userName = "default-user";
    options.password = "default-password";
    options.timeoutSecs = 30;
    options.privateKeyFile = "/tmp/client.ppk";
    options.hostKey = "SHA256:pinned";
    options.verbose = true;
    CHECK_TRUE(ParseSiteUrl("example.com", options, error));
    CHECK_TRUE(options.portNumber == 2200);
    CHECK_EQ(options.userName, "default-user");
    CHECK_EQ(options.password, "default-password");
    CHECK_TRUE(options.timeoutSecs == 30);
    CHECK_EQ(options.privateKeyFile, "/tmp/client.ppk");
    CHECK_EQ(options.hostKey, "SHA256:pinned");
    CHECK_TRUE(options.verbose);

    /* URI-escaped credentials and remote path are decoded. */
    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl(
        "sftp://url%40user:p%40ss%3Aword@example.com:2200/a%20b", options, error));
    CHECK_EQ(options.userName, "url@user");
    CHECK_EQ(options.password, "p@ss:word");
    CHECK_TRUE(options.portNumber == 2200);
    CHECK_EQ(options.initialDirectory, "/a b");

    /* No scheme at all. */
    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("example.com:2222/tmp", options, error));
    CHECK_EQ(options.hostName, "example.com");
    CHECK_TRUE(options.portNumber == 2222);
    CHECK_EQ(options.initialDirectory, "/tmp");

    /* The 'ssh' and 'scp' aliases of SFTP. */
    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("ssh://example.com", options, error));
    CHECK_EQ(options.hostName, "example.com");

    /* An IPv6 literal in brackets. */
    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("sftp://[::1]:2222/tmp", options, error));
    CHECK_EQ(options.hostName, "::1");
    CHECK_TRUE(options.portNumber == 2222);
    CHECK_EQ(options.initialDirectory, "/tmp");

    /* Multi-protocol URLs. */
    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("ftp://example.com", options, error));
    CHECK_EQ(options.protocol, "ftp");
    CHECK_EQ(options.hostName, "example.com");
    CHECK_TRUE(options.portNumber == 21);

    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("ftps://example.com", options, error));
    CHECK_EQ(options.protocol, "ftps");
    CHECK_TRUE(options.portNumber == 990);

    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("webdav://example.com/dav", options, error));
    CHECK_EQ(options.protocol, "webdav");
    CHECK_EQ(options.initialDirectory, "/dav");

    options = SessionOptions();
    CHECK_TRUE(ParseSiteUrl("s3://bucket.example.com", options, error));
    CHECK_EQ(options.protocol, "s3");

    /* Rejected URLs. */
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("gopher://example.com", options, error));
    CHECK_TRUE(error.find("Unsupported protocol") != std::string::npos);
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://", options, error));
    CHECK_TRUE(error.find("No host name") != std::string::npos);
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://example.com:0", options, error));
    CHECK_TRUE(error.find("Invalid port") != std::string::npos);
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://[::1", options, error));
    CHECK_TRUE(error.find("Malformed") != std::string::npos);
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://[::1]junk", options, error));
    CHECK_TRUE(error.find("Invalid port") != std::string::npos);
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://example.com:22junk", options, error));
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://[::1]:2222x", options, error));
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://example.com/%XZ", options, error));
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://user:secret@example.com:22junk", options, error));
    CHECK_TRUE(error.find("secret") == std::string::npos);
    options = SessionOptions();
    CHECK_FALSE(ParseSiteUrl("sftp://::1", options, error));
    CHECK_TRUE(error.find("brackets") != std::string::npos);
}

void TestLocalFs()
{
    const std::string dir = MakeTempDirectory();
    CHECK_TRUE(!dir.empty());
    if (dir.empty())
    {
        return;
    }
    std::string error;

    CHECK_TRUE(CreateLocalDirectory(dir, error));
    CHECK_TRUE(error.empty());
    CHECK_TRUE(CreateLocalDirectory(dir + "/sub", error));

    /* Binary mode: the size check below counts six bytes. */
    FILE * file = fopen((dir + "/one.txt").c_str(), "wb");
    CHECK_TRUE(file != NULL);
    if (file != NULL)
    {
        fputs("hello\n", file);
        fclose(file);
    }
    file = fopen((dir + "/two.log").c_str(), "wb");
    CHECK_TRUE(file != NULL);
    if (file != NULL)
    {
        fclose(file);
    }

    /* EEXIST is success only when the existing object is a directory. */
    CHECK_FALSE(CreateLocalDirectory(dir + "/one.txt", error));
    CHECK_TRUE(!error.empty());

    LocalFileInfo info = StatLocal(dir + "/one.txt");
    CHECK_TRUE(info.exists);
    CHECK_TRUE(info.error == 0);
    CHECK_FALSE(info.isDir);
    CHECK_TRUE(info.isRegular);
    CHECK_TRUE(info.size == 6);
    CHECK_TRUE(info.mtime > 0);
    info = StatLocal(dir + "/sub");
    CHECK_TRUE(info.exists);
    CHECK_TRUE(info.isDir);
    CHECK_FALSE(info.isRegular);
    info = StatLocal(dir + "/missing");
    CHECK_FALSE(info.exists);
    CHECK_TRUE(info.error == ENOENT);

    std::vector<std::string> names;
    CHECK_TRUE(ListLocalDirectory(dir, names, error));
    CHECK_TRUE(error.empty());
    CHECK_TRUE(names.size() == 3);
    CHECK_FALSE(ListLocalDirectory(dir + "/missing", names, error));
    CHECK_TRUE(!error.empty());
    CHECK_TRUE(ListLocalDirectory(dir, names, error));
    CHECK_TRUE(error.empty());

    names.clear();
    CHECK_TRUE(ExpandLocalWildcard(dir + "/*.txt", names, error));
    CHECK_TRUE(names.size() == 1);
    if (!names.empty())
    {
        CHECK_EQ(names[0], JoinLocalPath(dir, "one.txt"));
    }
    names.clear();
    CHECK_TRUE(ExpandLocalWildcard(dir + "/*", names, error));
    CHECK_TRUE(names.size() == 3);
    names.clear();
    /* A mask that matches nothing is not an error, it is just empty. */
    CHECK_TRUE(ExpandLocalWildcard(dir + "/*.none", names, error));
    CHECK_TRUE(names.empty());
    /* A plain name resolves to itself. */
    names.clear();
    CHECK_TRUE(ExpandLocalWildcard(dir + "/one.txt", names, error));
    CHECK_TRUE(names.size() == 1);

    /* The current local directory is restored, even after failed chdir. */
    const std::string originalDirectory = GetLocalDirectory(error);
    CHECK_TRUE(!originalDirectory.empty());
    CHECK_TRUE(SetLocalDirectory(dir, error));
    CHECK_EQ(GetLocalDirectory(error), dir);
    CHECK_FALSE(SetLocalDirectory(dir + "/missing", error));
    CHECK_TRUE(!error.empty());
    CHECK_TRUE(SetLocalDirectory(originalDirectory, error));

    CHECK_TRUE(RemoveLocalFile(dir + "/one.txt", error));
    CHECK_TRUE(RemoveLocalFile(dir + "/two.log", error));
    CHECK_EQ(error, "");
    CHECK_TRUE(RemoveDirectoryQuiet(dir + "/sub"));

    /* Recursive directory creation handles multiple missing parent directories. */
    CHECK_TRUE(CreateLocalDirectoryRecursive(dir + "/deep/nested/path", error));
    CHECK_TRUE(error.empty());
    LocalFileInfo deepInfo = StatLocal(dir + "/deep/nested/path");
    CHECK_TRUE(deepInfo.exists);
    CHECK_TRUE(deepInfo.isDir);
    CHECK_TRUE(RemoveDirectoryQuiet(dir + "/deep/nested/path"));
    CHECK_TRUE(RemoveDirectoryQuiet(dir + "/deep/nested"));
    CHECK_TRUE(RemoveDirectoryQuiet(dir + "/deep"));

    CHECK_TRUE(RemoveDirectoryQuiet(dir));
}

void TestScriptCommands()
{
    Script script;
    CHECK_TRUE(script.ExecuteLine("echo test message"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.ExecuteLine("option confirm off"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.ExecuteLine("option resume on"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.ExecuteLine("option resume off"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.ExecuteLine("option resume automatic"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.ExecuteLine("option batch abort"));
    CHECK_TRUE(script.ErrorCount() == 0);

    CHECK_TRUE(script.ExecuteLine("option transfer binary"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.ExecuteLine("binary"));
    CHECK_TRUE(script.ExecuteLine("option batch continue"));
    /* 'reconnect' is an unambiguous prefix of 'reconnecttime', so it is
     * accepted; a name that matches no option at all is still refused. */
    CHECK_TRUE(script.ExecuteLine("option reconnect 10"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.ExecuteLine("option reconnectxyz 10"));
    CHECK_TRUE(script.ErrorCount() == 1);
    CHECK_TRUE(script.ExecuteLine("option transfer ascii"));
    CHECK_TRUE(script.ErrorCount() == 1);
    CHECK_TRUE(script.ExecuteLine("option transfer"));
    CHECK_TRUE(script.ExecuteLine("option transfer automatic"));
    CHECK_TRUE(script.ExecuteLine("option transfer"));
    CHECK_TRUE(script.ExecuteLine("ascii"));
    CHECK_TRUE(script.ExecuteLine("binary"));
    /* include/exclude are one LinSCP mask: setting one clears the other. */
    CHECK_TRUE(script.ExecuteLine("option include *.txt"));
    CHECK_TRUE(script.ExecuteLine("option exclude *.bak;*.tmp"));
    CHECK_TRUE(script.ExecuteLine("option failonnomatch on"));
    CHECK_TRUE(script.ExecuteLine("option failonnomatch"));
    CHECK_TRUE(script.ExecuteLine("option echo on"));
    CHECK_TRUE(script.ExecuteLine("option synchdelete off"));
    CHECK_TRUE(script.ExecuteLine("option reconnecttime 30"));
    CHECK_TRUE(script.ExecuteLine("option reconnecttime off"));
    CHECK_TRUE(script.ExecuteLine("option reconnecttime nope"));
    CHECK_TRUE(script.ErrorCount() == 2);
    CHECK_FALSE(script.ExecuteLine("exit"));
    CHECK_TRUE(script.ExitRequested());

    Script aborting;
    CHECK_TRUE(aborting.ExecuteLine("option batch abort"));
    CHECK_FALSE(aborting.ExecuteLine("invalid-command"));
    CHECK_TRUE(aborting.ExitRequested());
    CHECK_TRUE(aborting.ErrorCount() == 1);
    CHECK_FALSE(aborting.ExecuteLine("option confirm off"));
    CHECK_TRUE(aborting.ErrorCount() == 1);
    Console::Instance().SetBatchMode(false);
}

void TestSessionRegistry()
{
    /* The SFTP transport adapter reaches the live session through this
     * pair, so it must start out empty and follow SetCurrentSession(). */
    CHECK_TRUE(CurrentSession() == NULL);
    Session session;
    CHECK_FALSE(session.IsOpen());
    CHECK_FALSE(session.IsAlive());
    SetCurrentSession(&session);
    CHECK_TRUE(CurrentSession() == &session);
    // No network I/O: this owner has no channel, so init leaves an error.
    CHECK_TRUE(lscp_sftp_init() != 0);
    const std::string originalError = lscp_sftp_error();
    CHECK_FALSE(originalError.empty());
    {
        Session auxiliary;
        auxiliary.Close();
    }
    CHECK_TRUE(CurrentSession() == &session);
    CHECK_EQ(lscp_sftp_error(), originalError);
    session.Close();
    CHECK_TRUE(CurrentSession() == NULL);
    CHECK_EQ(lscp_sftp_error(), "");
}

/* ------------------------------------------------------------------ *
 * Synchronization planning                                            *
 * ------------------------------------------------------------------ */

namespace {

/* An in-memory tree, so that the planner can be tested without a
 * server and without touching the file system. Paths are kept with '/'
 * on both sides and normalised on the way in, so that the same tree
 * works for the local side (whose separator is the host one) and for
 * the remote side (always POSIX). */
class MemoryFileSystem : public SyncFileSystem
{
public:
    MemoryFileSystem(const std::string & label, const std::string & root) :
        mLabel(label), mRoot(Normalize(root))
    {
        mDirectories[mRoot];
    }

    void AddFile(const std::string & path, unsigned long long size,
        unsigned long mtime)
    {
        Add(path, false, size, mtime);
    }

    /* A file with the checksum the planner sees for it. A file added
     * without one cannot be hashed at all, which is how the refusal of a
     * plan over a file nobody could read is tested. */
    void AddFile(const std::string & path, unsigned long long size,
        unsigned long mtime, const std::string & hash)
    {
        Add(path, false, size, mtime);
        mHashes[Normalize(mRoot + "/" + path)] = hash;
    }

    void AddDirectory(const std::string & path, unsigned long mtime)
    {
        Add(path, true, 0, mtime);
    }

    /* An existing but empty root, as opposed to a missing one. */
    void MakeRootListable() { mDirectories[mRoot]; }

    virtual bool ListDirectory(const std::string & path,
        std::vector<SyncEntry> & entries, std::string & error)
    {
        std::string key = Normalize(path);
        while (key.size() > 1 && key[key.size() - 1] == '/')
        {
            key.erase(key.size() - 1);
        }
        std::map<std::string, std::vector<SyncEntry> >::const_iterator it =
            mDirectories.find(key);
        if (it == mDirectories.end())
        {
            error = "no such directory";
            return false;
        }
        entries = it->second;
        return true;
    }

    virtual const char * Label() const { return mLabel.c_str(); }

    virtual bool HashFile(const std::string & path, std::string & hash,
        std::string & error)
    {
        const std::map<std::string, std::string>::const_iterator found =
            mHashes.find(Normalize(path));
        if (found == mHashes.end())
        {
            error = std::string("the ") + mLabel + " side has no checksum "
                "for it";
            return false;
        }
        hash = found->second;
        return true;
    }

private:
    static std::string Normalize(const std::string & path)
    {
        std::string result = path;
        for (size_t i = 0; i < result.size(); i++)
        {
            if (result[i] == '\\')
            {
                result[i] = '/';
            }
        }
        return result;
    }

    bool HasEntry(const std::string & directory, const std::string & name) const
    {
        std::map<std::string, std::vector<SyncEntry> >::const_iterator it =
            mDirectories.find(directory);
        if (it == mDirectories.end())
        {
            return false;
        }
        for (size_t i = 0; i < it->second.size(); i++)
        {
            if (it->second[i].name == name)
            {
                return true;
            }
        }
        return false;
    }

    void Add(const std::string & path, bool isDirectory, unsigned long long size,
        unsigned long mtime)
    {
        const std::vector<std::string> parts = SplitRelativePath(Normalize(path));
        if (parts.empty())
        {
            return;
        }
        std::string walk = mRoot;
        for (size_t i = 0; i + 1 < parts.size(); i++)
        {
            if (!HasEntry(walk, parts[i]))
            {
                SyncEntry parent;
                parent.name = parts[i];
                parent.isDirectory = true;
                mDirectories[walk].push_back(parent);
            }
            walk += "/" + parts[i];
            mDirectories[walk];
        }
        SyncEntry entry;
        entry.name = parts.back();
        entry.isDirectory = isDirectory;
        entry.size = size;
        entry.mtime = mtime;
        if (!HasEntry(walk, entry.name))
        {
            mDirectories[walk].push_back(entry);
        }
        if (isDirectory)
        {
            mDirectories[walk + "/" + entry.name];
        }
    }

    std::map<std::string, std::vector<SyncEntry> > mDirectories;
    std::map<std::string, std::string> mHashes;
    std::string mLabel;
    std::string mRoot;
};

/* The criteria one '-criteria=' value describes, or a failed check. */
SyncCriteria CriteriaOf(const char * text)
{
    SyncCriteria criteria;
    std::string error;
    CHECK_TRUE(ParseSyncCriteria(text, criteria, error));
    return criteria;
}

const SyncItem * FindItem(const SyncPlan & plan, const std::string & path)
{
    for (size_t i = 0; i < plan.items.size(); i++)
    {
        if (plan.items[i].path == path)
        {
            return &plan.items[i];
        }
    }
    return NULL;
}

SyncAction ActionOf(const SyncPlan & plan, const std::string & path)
{
    const SyncItem * item = FindItem(plan, path);
    return item != NULL ? item->action : SyncAction::None;
}

bool RemoveTreeQuiet(const std::string & path)
{
    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::path(path), ec);
    return !ec;
}

} // namespace

void TestFileMaskParsing()
{
    FileMask mask;
    std::string error;

    CHECK_TRUE(mask.Parse("*.txt", error));
    CHECK_TRUE(mask.include.size() == 1);
    CHECK_TRUE(mask.exclude.empty());
    CHECK_TRUE(mask.Accepts("a.txt", false));
    CHECK_FALSE(mask.Accepts("a.log", false));
    /* An include mask never prunes a directory. */
    CHECK_TRUE(mask.Accepts("logs", true));

    CHECK_TRUE(mask.Parse("*.txt|*.bak", error));
    CHECK_TRUE(mask.include.size() == 1);
    CHECK_TRUE(mask.exclude.size() == 1);
    CHECK_TRUE(mask.Accepts("a.txt", false));
    CHECK_FALSE(mask.Accepts("a.bak", false));
    CHECK_TRUE(mask.Accepts("logs", true));
    CHECK_FALSE(mask.Accepts("cache.bak", true));

    CHECK_TRUE(mask.Parse("|*.bak;*.tmp", error));
    CHECK_TRUE(mask.include.empty());
    CHECK_TRUE(mask.exclude.size() == 2);
    CHECK_TRUE(mask.Accepts("anything", false));
    CHECK_FALSE(mask.Accepts("a.bak", false));
    CHECK_FALSE(mask.Accepts("a.tmp", false));
    /* Exclusions do prune a directory. */
    CHECK_FALSE(mask.Accepts("cache.tmp", true));

    CHECK_TRUE(mask.Parse("*.txt;*.md", error));
    CHECK_TRUE(mask.include.size() == 2);
    CHECK_TRUE(mask.Accepts("readme.md", false));
    CHECK_FALSE(mask.Accepts("a.log", false));

    /* An empty mask selects everything. */
    CHECK_TRUE(mask.Parse("", error));
    CHECK_TRUE(mask.empty());
    CHECK_EQ(mask.Describe(), "(none)");

    /* Directory masks end with '/': they match directories only. */
    CHECK_TRUE(mask.Parse("*/build/", error));
    CHECK_FALSE(mask.Accepts("build", false));
    CHECK_TRUE(mask.Accepts("build", true));
    CHECK_FALSE(mask.Accepts("docs", true));

    /* Path masks match the path of a file below the transfer root;
     * they do not address directories (use a trailing '/' for that). */
    CHECK_TRUE(mask.Parse("sub/*.txt", error));
    CHECK_FALSE(mask.Accepts("a.txt", false, 0, 0, "a.txt"));
    CHECK_FALSE(mask.Accepts("a.txt", false, 0, 0, "other/a.txt"));
    CHECK_TRUE(mask.Accepts("a.txt", false, 0, 0, "sub/a.txt"));
    CHECK_FALSE(mask.Accepts("sub", true, 0, 0, "sub"));

    /* Exclusion by directory mask prunes a subtree at any depth. */
    CHECK_TRUE(mask.Parse("|*/node_modules/;*.tmp", error));
    CHECK_TRUE(mask.Accepts("app", true, 0, 0, "app"));
    CHECK_FALSE(mask.Accepts("app", true, 0, 0, "node_modules"));
    CHECK_FALSE(mask.Accepts("app", true, 0, 0, "web/node_modules"));
    CHECK_FALSE(mask.Accepts("a.tmp", false, 0, 0, "a.tmp"));

    /* Size criteria: 1K is 1024 bytes, 1M is 1024*1024. */
    CHECK_TRUE(mask.Parse("*.bin>1K", error));
    CHECK_TRUE(mask.Accepts("a.bin", false, 1025, 0, "a.bin"));
    CHECK_FALSE(mask.Accepts("a.bin", false, 1024, 0, "a.bin"));
    CHECK_FALSE(mask.Accepts("a.bin", false, 0, 0, "a.bin"));
    /* A mask with a size criterion never selects a directory (an
     * include mask still never prunes one). */
    CHECK_TRUE(mask.Accepts("a.bin", true, 5000000, 0, "a.bin"));
    CHECK_TRUE(mask.Parse("|*.bin>1K", error));
    CHECK_FALSE(mask.Accepts("a.bin", false, 5000000, 0, "a.bin"));
    CHECK_TRUE(mask.Accepts("a.bin", true, 5000000, 0, "a.bin"));

    CHECK_TRUE(mask.Parse("*.bin<=1M", error));
    CHECK_TRUE(mask.Accepts("a.bin", false, 1024 * 1024, 0, "a.bin"));
    CHECK_FALSE(mask.Accepts("a.bin", false, 1024 * 1024 + 1, 0, "a.bin"));

    /* Time criteria are local dates, optionally with a time of day. */
    CHECK_TRUE(mask.Parse("*.log>=2020-06-01", error));
    const unsigned long juneFirst2020 = 1590969600UL; /* 2020-06-01 UTC */
    CHECK_FALSE(mask.Accepts("a.log", false, 10, juneFirst2020 - 86400, "a.log"));
    CHECK_TRUE(mask.Accepts("a.log", false, 10, juneFirst2020 + 86400, "a.log"));
    CHECK_TRUE(mask.Accepts("a.log", false, 10, juneFirst2020, "a.log"));
    CHECK_FALSE(mask.Accepts("a.log", false, 10, 0, "a.log"));

    /* Criteria chain within one token. */
    CHECK_TRUE(mask.Parse("*.dat>1K<10K", error));
    CHECK_TRUE(mask.Accepts("a.dat", false, 4096, 0, "a.dat"));
    CHECK_FALSE(mask.Accepts("a.dat", false, 20000, 0, "a.dat"));
    CHECK_FALSE(mask.Accepts("a.dat", false, 100, 0, "a.dat"));

    /* A token with only a criterion means '*<criterion>'. */
    CHECK_TRUE(mask.Parse(">2K", error));
    CHECK_TRUE(mask.Accepts("anything", false, 4096, 0, "anything"));
    CHECK_FALSE(mask.Accepts("anything", false, 100, 0, "anything"));

    /* Invalid criteria fail explicitly. */
    CHECK_FALSE(mask.Parse("*.txt>1X", error));
    CHECK_FALSE(error.empty());
    CHECK_FALSE(mask.Parse("*.txt>notadate", error));
    CHECK_FALSE(error.empty());
    CHECK_FALSE(mask.Parse("*.txt>=2026-13-40", error));
    CHECK_FALSE(error.empty());
    CHECK_EQ(mask.Describe(), "(none)");
}

void TestSyncPlannerModes()
{
    MemoryFileSystem local("local", "/local");
    MemoryFileSystem remote("remote", "/remote");
    std::string error;

    /* same.txt:        identical on both sides
     * older.txt:       the remote copy is newer
     * only-remote.txt: only on the remote side
     * only-local.txt:  only on the local side */
    local.AddFile("same.txt", 10, 1000);
    remote.AddFile("same.txt", 10, 1000);
    local.AddFile("older.txt", 10, 1000);
    remote.AddFile("older.txt", 20, 2000);
    remote.AddFile("only-remote.txt", 5, 1500);
    local.AddFile("only-local.txt", 7, 1500);

    SyncOptions options;
    SyncPlan plan;

    /* Local: the remote tree wins. */
    options.mode = SyncMode::Local;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_EQ(error, "");
    CHECK_TRUE(ActionOf(plan, "same.txt") == SyncAction::None);
    CHECK_TRUE(ActionOf(plan, "older.txt") == SyncAction::Download);
    CHECK_TRUE(ActionOf(plan, "only-remote.txt") == SyncAction::Download);
    CHECK_TRUE(ActionOf(plan, "only-local.txt") == SyncAction::None);
    CHECK_FALSE(plan.DeletesAnything());

    /* -delete removes what the winning side does not have. */
    options.deleteObsolete = true;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "only-local.txt") == SyncAction::DeleteLocal);
    CHECK_TRUE(plan.DeletesAnything());
    options.deleteObsolete = false;

    /* Remote: the local tree wins. */
    options.mode = SyncMode::Remote;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "older.txt") == SyncAction::None);
    CHECK_TRUE(ActionOf(plan, "only-local.txt") == SyncAction::Upload);
    CHECK_TRUE(ActionOf(plan, "only-remote.txt") == SyncAction::None);
    options.deleteObsolete = true;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "only-remote.txt") == SyncAction::DeleteRemote);
    options.deleteObsolete = false;

    /* Both, without a previous state: the newer side wins. */
    options.mode = SyncMode::Both;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "older.txt") == SyncAction::Download);
    CHECK_TRUE(ActionOf(plan, "only-remote.txt") == SyncAction::Download);
    CHECK_TRUE(ActionOf(plan, "only-local.txt") == SyncAction::Upload);
    CHECK_TRUE(ActionOf(plan, "same.txt") == SyncAction::None);
    /* Without a state nothing is deleted, whatever the switches say. */
    options.deleteObsolete = true;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_FALSE(plan.DeletesAnything());
    options.deleteObsolete = false;
}

void TestSyncPlannerCriteria()
{
    MemoryFileSystem local("local", "/local");
    MemoryFileSystem remote("remote", "/remote");
    std::string error;

    /* The remote file is older but larger. */
    local.AddFile("file.txt", 10, 2000);
    remote.AddFile("file.txt", 30, 1000);

    SyncOptions options;
    options.mode = SyncMode::Local;
    SyncPlan plan;

    options.criteria = CriteriaOf("time");
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "file.txt") == SyncAction::None);

    options.criteria = CriteriaOf("size");
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "file.txt") == SyncAction::Download);

    options.criteria = CriteriaOf("either");
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "file.txt") == SyncAction::Download);
    /* 'both' is upstream's other word for the same pair. */
    CHECK_TRUE(CriteriaOf("both") == CriteriaOf("either"));

    options.criteria = CriteriaOf("none");
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "file.txt") == SyncAction::Download);

    /* A list compares what it names: 'checksum' alone reaches two files
     * the timestamps and the sizes call equal. */
    MemoryFileSystem hashedLocal("local", "/local");
    MemoryFileSystem hashedRemote("remote", "/remote");
    hashedLocal.AddFile("same.txt", 10, 2000, "aa");
    hashedRemote.AddFile("same.txt", 10, 2000, "aa");
    hashedLocal.AddFile("edited.txt", 10, 2000, "aa");
    hashedRemote.AddFile("edited.txt", 10, 2000, "bb");
    SyncPlan contents;

    options.criteria = CriteriaOf("checksum");
    CHECK_TRUE(PlanSynchronization(hashedLocal, hashedRemote, "/local",
        "/remote", options, contents, error));
    CHECK_TRUE(ActionOf(contents, "same.txt") == SyncAction::None);
    CHECK_TRUE(ActionOf(contents, "edited.txt") == SyncAction::Download);

    /* The reason names the comparison that found the difference. */
    const SyncItem * edited = FindItem(contents, "edited.txt");
    CHECK_TRUE(edited != NULL);
    CHECK_TRUE(edited->reason.find("contents differ") != std::string::npos);

    /* 'time,checksum' still leaves the newer file alone in a download:
     * the remote copy is not newer, so only the contents can differ. */
    options.criteria = CriteriaOf("time,checksum");
    CHECK_TRUE(PlanSynchronization(hashedLocal, hashedRemote, "/local",
        "/remote", options, contents, error));
    CHECK_TRUE(ActionOf(contents, "edited.txt") == SyncAction::Download);

    /* A file that cannot be hashed is not an agreement: the plan is
     * refused with the reason instead of calling the two sides equal. */
    MemoryFileSystem opaqueLocal("local", "/local");
    MemoryFileSystem opaqueRemote("remote", "/remote");
    opaqueLocal.AddFile("file.txt", 10, 2000);          /* no checksum */
    opaqueRemote.AddFile("file.txt", 10, 2000, "aa");
    options.criteria = CriteriaOf("checksum");
    CHECK_FALSE(PlanSynchronization(opaqueLocal, opaqueRemote, "/local",
        "/remote", options, contents, error));
    CHECK_TRUE(error.find("Cannot compare the checksum") != std::string::npos);
    CHECK_TRUE(error.find("no checksum for it") != std::string::npos);
}

void TestSyncCriteriaParsing()
{
    /* Every word upstream accepts, and the combinations a list makes. */
    CHECK_TRUE(CriteriaOf("none").Empty());
    CHECK_TRUE(CriteriaOf("NONE").Empty());
    CHECK_TRUE(CriteriaOf("time").time && !CriteriaOf("time").size &&
        !CriteriaOf("time").checksum);
    CHECK_TRUE(!CriteriaOf("size").time && CriteriaOf("size").size);
    CHECK_TRUE(CriteriaOf("checksum").checksum && !CriteriaOf("checksum").time);
    CHECK_TRUE(CriteriaOf("either").time && CriteriaOf("either").size &&
        !CriteriaOf("either").checksum);
    CHECK_TRUE(CriteriaOf("both") == CriteriaOf("either"));
    CHECK_TRUE(CriteriaOf("time,size") == CriteriaOf("either"));
    CHECK_TRUE(CriteriaOf("time,checksum").time &&
        CriteriaOf("time,checksum").checksum &&
        !CriteriaOf("time,checksum").size);
    CHECK_TRUE(CriteriaOf("size,checksum").size &&
        CriteriaOf("size,checksum").checksum);
    CHECK_TRUE(CriteriaOf("time,size,checksum").time &&
        CriteriaOf("time,size,checksum").size &&
        CriteriaOf("time,size,checksum").checksum);
    /* Spaces around an item are tolerated, and an item may repeat. */
    CHECK_TRUE(CriteriaOf("time , checksum") == CriteriaOf("time,checksum"));
    CHECK_TRUE(CriteriaOf("size,size") == CriteriaOf("size"));

    /* The names a plan prints: the words, and the list for the rest. */
    CHECK_EQ(SyncCriteriaName(CriteriaOf("none")), std::string("none"));
    CHECK_EQ(SyncCriteriaName(CriteriaOf("time")), std::string("time"));
    CHECK_EQ(SyncCriteriaName(CriteriaOf("size")), std::string("size"));
    CHECK_EQ(SyncCriteriaName(CriteriaOf("checksum")), std::string("checksum"));
    CHECK_EQ(SyncCriteriaName(CriteriaOf("either")), std::string("either"));
    CHECK_EQ(SyncCriteriaName(CriteriaOf("time,checksum")),
        std::string("time,checksum"));
    CHECK_EQ(SyncCriteriaName(CriteriaOf("size,checksum")),
        std::string("size,checksum"));
    CHECK_EQ(SyncCriteriaName(CriteriaOf("time,size,checksum")),
        std::string("time,size,checksum"));
    /* The default is the one '-criteria=time' describes. */
    CHECK_TRUE(SyncOptions().criteria == CriteriaOf("time"));

    /* Anything else is refused, and the refusal names the words that
     * are known. */
    const char * const rejected[] = { "", "whenever", "timestamp", "time,",
        ",size", "time,,size", "none,time", "time,none", "either,size",
        "sha256", "check", "times" };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
    {
        SyncCriteria criteria;
        std::string error;
        CHECK_FALSE(ParseSyncCriteria(rejected[i], criteria, error));
        CHECK_TRUE(!error.empty());
    }
    SyncCriteria criteria;
    std::string error;
    CHECK_FALSE(ParseSyncCriteria("", criteria, error));
    CHECK_TRUE(error.find("needs a value") != std::string::npos);
    CHECK_FALSE(ParseSyncCriteria("whenever", criteria, error));
    CHECK_TRUE(error.find("Unsupported criteria 'whenever'") != std::string::npos);
    CHECK_TRUE(error.find("checksum") != std::string::npos);
    CHECK_FALSE(ParseSyncCriteria("time,", criteria, error));
    CHECK_TRUE(error.find("empty item") != std::string::npos);
    CHECK_FALSE(ParseSyncCriteria("none,time", criteria, error));
    CHECK_TRUE(error.find("whole set of criteria") != std::string::npos);
}

void TestSyncPlannerMaskAndRecursion()
{
    MemoryFileSystem local("local", "/local");
    MemoryFileSystem remote("remote", "/remote");
    std::string error;

    remote.AddDirectory("sub", 1000);
    remote.AddFile("sub/keep.txt", 4, 1200);
    remote.AddFile("sub/skip.log", 4, 1200);
    remote.AddFile("top.txt", 2, 1200);

    SyncOptions options;
    options.mode = SyncMode::Local;
    SyncPlan plan;
    CHECK_TRUE(options.mask.Parse("*.txt", error));

    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "sub/keep.txt") == SyncAction::Download);
    CHECK_FALSE(FindItem(plan, "sub/skip.log") != NULL);
    CHECK_TRUE(ActionOf(plan, "top.txt") == SyncAction::Download);

    /* Non-recursive: only the top directory is compared. */
    options.recursive = false;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(ActionOf(plan, "top.txt") == SyncAction::Download);
    CHECK_FALSE(FindItem(plan, "sub/keep.txt") != NULL);

    /* A directory that only one side has is planned as a whole subtree. */
    options.recursive = true;
    options.mask = FileMask();
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    const SyncItem * sub = FindItem(plan, "sub");
    CHECK_TRUE(sub != NULL && sub->isDirectory);
    CHECK_TRUE(sub != NULL && sub->action == SyncAction::Download);
    CHECK_TRUE(ActionOf(plan, "sub/skip.log") == SyncAction::Download);

    /* Plan paths are rebuilt with the separator of each side. */
    CHECK_EQ(LocalPathForRelative("/local", "sub/keep.txt"),
        JoinLocalPath(JoinLocalPath("/local", "sub"), "keep.txt"));
    CHECK_EQ(RemotePathForRelative("/remote", "sub/keep.txt"), "/remote/sub/keep.txt");
    CHECK_EQ(LocalPathForRelative("/local", ""), "/local");
}

void TestSyncPlannerConflictsAndState()
{
    MemoryFileSystem local("local", "/local");
    MemoryFileSystem remote("remote", "/remote");
    std::string error;

    local.AddFile("recorded.txt", 10, 1000);
    remote.AddFile("recorded.txt", 10, 1000);
    local.AddFile("deleted-on-remote.txt", 3, 1000);
    local.AddFile("new-locally.txt", 4, 1000);
    remote.AddFile("new-remotely.txt", 5, 1000);

    /* The state of the last synchronization: everything was equal except
     * for the file that has since been deleted on the remote side. */
    SyncState state;
    SyncStateEntry recorded;
    recorded.localTime = 1000;
    recorded.remoteTime = 1000;
    recorded.size = 10;
    state.Update("recorded.txt", recorded);
    recorded.size = 3;
    state.Update("deleted-on-remote.txt", recorded);

    SyncOptions options;
    options.mode = SyncMode::Both;
    options.deleteObsolete = true;
    options.state = &state;
    SyncPlan plan;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));

    /* Known on both sides and unchanged since: nothing to do. */
    CHECK_TRUE(ActionOf(plan, "recorded.txt") == SyncAction::None);
    /* Unknown to the state: new on one side, so it is copied. */
    CHECK_TRUE(ActionOf(plan, "new-locally.txt") == SyncAction::Upload);
    CHECK_TRUE(ActionOf(plan, "new-remotely.txt") == SyncAction::Download);
    /* It was on the remote side at the last pass and is gone now, so the
     * deletion is carried over to the local side instead of being read
     * as a new local file. */
    CHECK_TRUE(ActionOf(plan, "deleted-on-remote.txt") == SyncAction::DeleteLocal);

    /* Both sides changed since the last pass: a conflict, never a guess. */
    MemoryFileSystem local2("local", "/local");
    MemoryFileSystem remote2("remote", "/remote");
    local2.AddFile("recorded.txt", 11, 2000);
    remote2.AddFile("recorded.txt", 12, 3000);
    SyncPlan conflictPlan;
    CHECK_TRUE(PlanSynchronization(local2, remote2, "/local", "/remote",
        options, conflictPlan, error));
    CHECK_TRUE(ActionOf(conflictPlan, "recorded.txt") == SyncAction::Conflict);
    CHECK_TRUE(conflictPlan.HasConflicts());
    /* A plan with conflicts never deletes anything. */
    CHECK_FALSE(conflictPlan.DeletesAnything());

    /* Explicit conflict policies resolve the conflict deterministically. */
    SyncOptions resolvedOptions = options;
    CHECK_TRUE(ParseSyncConflictPolicy("local",
        resolvedOptions.conflictPolicy, error));
    SyncPlan resolvedLocal;
    CHECK_TRUE(PlanSynchronization(local2, remote2, "/local", "/remote",
        resolvedOptions, resolvedLocal, error));
    CHECK_TRUE(ActionOf(resolvedLocal, "recorded.txt") == SyncAction::Upload);
    CHECK_FALSE(resolvedLocal.HasConflicts());

    CHECK_TRUE(ParseSyncConflictPolicy("remote",
        resolvedOptions.conflictPolicy, error));
    SyncPlan resolvedRemote;
    CHECK_TRUE(PlanSynchronization(local2, remote2, "/local", "/remote",
        resolvedOptions, resolvedRemote, error));
    CHECK_TRUE(ActionOf(resolvedRemote, "recorded.txt") == SyncAction::Download);

    CHECK_TRUE(ParseSyncConflictPolicy("newer",
        resolvedOptions.conflictPolicy, error));
    SyncPlan resolvedNewer;
    CHECK_TRUE(PlanSynchronization(local2, remote2, "/local", "/remote",
        resolvedOptions, resolvedNewer, error));
    CHECK_TRUE(ActionOf(resolvedNewer, "recorded.txt") == SyncAction::Download);
    CHECK_FALSE(ParseSyncConflictPolicy("unknown-policy",
        resolvedOptions.conflictPolicy, error));

    /* One side changed: that side wins. */
    MemoryFileSystem local3("local", "/local");
    MemoryFileSystem remote3("remote", "/remote");
    local3.AddFile("recorded.txt", 11, 2000);
    remote3.AddFile("recorded.txt", 10, 1000);
    SyncPlan localWins;
    CHECK_TRUE(PlanSynchronization(local3, remote3, "/local", "/remote",
        options, localWins, error));
    CHECK_TRUE(ActionOf(localWins, "recorded.txt") == SyncAction::Upload);

    MemoryFileSystem local4("local", "/local");
    MemoryFileSystem remote4("remote", "/remote");
    local4.AddFile("recorded.txt", 10, 1000);
    remote4.AddFile("recorded.txt", 13, 4000);
    SyncPlan remoteWins;
    CHECK_TRUE(PlanSynchronization(local4, remote4, "/local", "/remote",
        options, remoteWins, error));
    CHECK_TRUE(ActionOf(remoteWins, "recorded.txt") == SyncAction::Download);
}

void TestSyncPlanOrder()
{
    /* Transfers are applied before deletions, and deletions deepest
     * first, so that a directory is empty by the time it is removed. */
    MemoryFileSystem local("local", "/local");
    MemoryFileSystem remote("remote", "/remote");
    local.MakeRootListable();
    local.AddDirectory("sub", 1000);
    local.AddFile("keep.txt", 10, 5000);
    remote.AddDirectory("sub", 1000);
    remote.AddFile("keep.txt", 10, 1000);
    remote.AddFile("old.txt", 2, 1);
    remote.AddFile("sub/old.txt", 2, 1);
    std::string error;

    SyncOptions options;
    options.mode = SyncMode::Remote;
    options.deleteObsolete = true;
    SyncPlan plan;
    CHECK_TRUE(PlanSynchronization(local, remote, "/local", "/remote",
        options, plan, error));
    CHECK_TRUE(plan.items.size() == 3);
    if (plan.items.size() == 3)
    {
        CHECK_EQ(plan.items[0].path, "keep.txt");
        CHECK_TRUE(plan.items[0].action == SyncAction::Upload);
        CHECK_TRUE(plan.items[1].action == SyncAction::DeleteRemote);
        CHECK_EQ(plan.items[1].path, "sub/old.txt");
        CHECK_TRUE(plan.items[2].action == SyncAction::DeleteRemote);
        CHECK_EQ(plan.items[2].path, "old.txt");
    }

    /* A whole directory that only one side has is removed in one item,
     * not one per file. */
    MemoryFileSystem emptyLocal("local", "/local");
    MemoryFileSystem onlyRemote("remote", "/remote");
    emptyLocal.MakeRootListable();
    onlyRemote.AddDirectory("gone", 1);
    onlyRemote.AddFile("gone/inside.txt", 2, 1);
    SyncPlan treePlan;
    CHECK_TRUE(PlanSynchronization(emptyLocal, onlyRemote, "/local", "/remote",
        options, treePlan, error));
    CHECK_TRUE(treePlan.items.size() == 1);
    CHECK_TRUE(treePlan.items.size() == 1 && treePlan.items[0].path == "gone");
    CHECK_TRUE(treePlan.items.size() == 1 && treePlan.items[0].isDirectory);
}

void TestSyncStateFile()
{
    const std::string temporary = MakeTempDirectory();
    if (temporary.empty())
    {
        return;
    }
    const char * oldConfig = getenv("LINSCP_CONFIG_DIR");
    const bool hadConfig = oldConfig != NULL;
    const std::string savedConfig = hadConfig ? oldConfig : "";
    SetEnvVar("LINSCP_CONFIG_DIR", temporary.c_str());

    const std::string key = SyncState::MakeKey("host", "/local", "/remote");
    CHECK_FALSE(key.empty());
    CHECK_TRUE(SyncState::MakeKey("host", "/local", "/remote") == key);
    CHECK_FALSE(SyncState::MakeKey("other", "/local", "/remote") == key);

    const std::string path = SyncState::DefaultPath(key);
    CHECK_FALSE(path.empty());

    SyncState state;
    SyncStateEntry entry;
    entry.localTime = 111;
    entry.remoteTime = 222;
    entry.size = 4096;
    state.Update("dir/file name.txt", entry);
    entry.localTime = 333;
    state.Update("plain.txt", entry);
    std::string error;
    CHECK_TRUE(state.Save(path, error));
    CHECK_TRUE(state.Size() == 2);

    SyncState reloaded;
    CHECK_TRUE(reloaded.Load(path, error));
    CHECK_TRUE(reloaded.Size() == 2);
    SyncStateEntry back;
    CHECK_TRUE(reloaded.Lookup("dir/file name.txt", back));
    CHECK_TRUE(back.localTime == 111);
    CHECK_TRUE(back.remoteTime == 222);
    CHECK_TRUE(back.size == 4096);
    CHECK_FALSE(reloaded.Lookup("missing", back));

    reloaded.Remove("plain.txt");
    CHECK_TRUE(reloaded.Size() == 1);
    CHECK_TRUE(reloaded.Save(path, error));

    SyncState afterRemoval;
    CHECK_TRUE(afterRemoval.Load(path, error));
    CHECK_TRUE(afterRemoval.Size() == 1);
    CHECK_FALSE(afterRemoval.Lookup("plain.txt", back));

    /* A missing state file is an empty state, not an error. */
    SyncState missingState;
    CHECK_TRUE(missingState.Load(path + ".does-not-exist", error));
    CHECK_TRUE(missingState.Empty());

    SetEnvVar("LINSCP_CONFIG_DIR", hadConfig ? savedConfig.c_str() : NULL);
    RemoveTreeQuiet(temporary);
}

/* ------------------------------------------------------------------ *
 * Amazon S3 request signing (AWS Signature Version 4)                 *
 * ------------------------------------------------------------------ */

/*
 * The vectors come from outside this code: the signing key is the
 * worked example in AWS's "Signature Version 4 signing process"
 * documentation (20150830 / us-east-1 / iam), and the two requests
 * were signed by botocore 1.43 with a frozen clock (2026-01-15
 * 10:30:00 UTC = epoch 1768473000). If any step of the construction
 * here drifts, one of them stops matching.
 */
void TestS3SigV4()
{
    using namespace linscp::s3sig;

    const std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    CHECK_EQ(HexEncode(SigningKey(secret, "20150830", "us-east-1", "iam")),
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");

    /* Encoding rules: the S3 flavor, '~' kept, uppercase hex. */
    CHECK_EQ(UriEncode("a b/c+d~e", true), "a%20b/c%2Bd~e");
    CHECK_EQ(UriEncode("a b/c+d~e", false), "a%20b%2Fc%2Bd~e");
    CHECK_EQ(CanonicalQuery("b=2&a=1&a=0&a=10"), "a=0&a=1&a=10&b=2");
    CHECK_EQ(CredentialScope("20260115", "us-east-1", "s3"),
        "20260115/us-east-1/s3/aws4_request");
    CHECK_EQ(AmzDate(1768473000ULL), "20260115T103000Z");
    CHECK_EQ(DateStamp(1768473000ULL), "20260115");
    CHECK_EQ(AmzDate(~0ULL), "");
    CHECK_EQ(DateStamp(~0ULL), "");

    const std::string emptyHash =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /* A signed ListObjectsV2-style GET. */
    std::vector<std::pair<std::string, std::string> > headers;
    headers.push_back(std::make_pair("x-amz-date", "20260115T103000Z"));
    headers.push_back(std::make_pair("host", "s3.example.com"));
    headers.push_back(std::make_pair("x-amz-content-sha256", emptyHash));
    const std::string canonical = CanonicalRequest("GET", "/bucket",
        "delimiter=%2F&list-type=2&max-keys=100&prefix=docs%2Fa",
        headers, emptyHash);
    const std::string expectedCanonical =
        "GET\n"
        "/bucket\n"
        "delimiter=%2F&list-type=2&max-keys=100&prefix=docs%2Fa\n"
        "host:s3.example.com\n"
        "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "x-amz-date:20260115T103000Z\n"
        "\n"
        "host;x-amz-content-sha256;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    CHECK_EQ(canonical, expectedCanonical);
    const std::string scope = CredentialScope("20260115", "us-east-1", "s3");
    const std::string toSign = StringToSign("20260115T103000Z", scope,
        canonical);
    const std::string signature = SignatureHex(toSign,
        SigningKey(secret, "20260115", "us-east-1", "s3"));
    CHECK_EQ(signature,
        "7d151aa653d4a54778780085f0edbe6d135ed056a28e85bada65053d6e2e35ba");
    CHECK_EQ(AuthorizationHeader("AKIDEXAMPLE", scope,
                 "host;x-amz-content-sha256;x-amz-date", signature),
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260115/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=7d151aa653d4a54778780085f0edbe6d135ed056a28e85bada65053d6e2e35ba");

    /* And the whole Sign() pipeline, which must land on the same bytes
     * (this is what the client actually calls). */
    SignedRequest signed1 = Sign("GET", "/bucket",
        "delimiter=%2F&list-type=2&max-keys=100&prefix=docs%2Fa",
        "s3.example.com", std::vector<std::pair<std::string, std::string> >(),
        emptyHash, 1768473000ULL, "us-east-1", "AKIDEXAMPLE", secret);
    CHECK_EQ(signed1.canonicalRequest, expectedCanonical);
    CHECK_EQ(signed1.signedHeaders, "host;x-amz-content-sha256;x-amz-date");
    CHECK_EQ(signed1.authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260115/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=7d151aa653d4a54778780085f0edbe6d135ed056a28e85bada65053d6e2e35ba");

    /* A PUT with reserved characters in the key, UNSIGNED-PAYLOAD. */
    std::vector<std::pair<std::string, std::string> > putHeaders;
    putHeaders.push_back(std::make_pair("x-amz-date", "20260115T103000Z"));
    putHeaders.push_back(std::make_pair("host", "s3.example.com"));
    putHeaders.push_back(std::make_pair("x-amz-content-sha256",
        "UNSIGNED-PAYLOAD"));
    const std::string canonical2 = CanonicalRequest("PUT",
        "/bucket/hello%20world%2Bdir/f.txt", "",
        putHeaders, "UNSIGNED-PAYLOAD");
    const std::string expectedCanonical2 =
        "PUT\n"
        "/bucket/hello%20world%2Bdir/f.txt\n"
        "\n"
        "host:s3.example.com\n"
        "x-amz-content-sha256:UNSIGNED-PAYLOAD\n"
        "x-amz-date:20260115T103000Z\n"
        "\n"
        "host;x-amz-content-sha256;x-amz-date\n"
        "UNSIGNED-PAYLOAD";
    CHECK_EQ(canonical2, expectedCanonical2);
    const std::string signature2 = SignatureHex(
        StringToSign("20260115T103000Z", scope, canonical2),
        SigningKey(secret, "20260115", "us-east-1", "s3"));
    CHECK_EQ(signature2,
        "4e1f492da78c20e5bab873603c6ba95cba1ffd7b22d0275497cb4cc3d2dfbc56");
}

/* ------------------------------------------------------------------ *
 * Stored sessions                                                     *
 * ------------------------------------------------------------------ */

/*
 * The proxy of a session: upstream's setting names, its method vocabulary,
 * and the checks that stop a configuration the transport cannot honour
 * before a connection is attempted.
 */
void TestProxySettings()
{
    /* Upstream's names - and the numbers it stores them as. */
    const struct { const char * text; ProxyMethod method; } names[] = {
        { "None", ProxyMethod::None },
        { "socks4", ProxyMethod::Socks4 },
        { "SOCKS5", ProxyMethod::Socks5 },
        { "http", ProxyMethod::Http },
        { "Telnet", ProxyMethod::Telnet },
        { "Cmd", ProxyMethod::Local },
        { "local", ProxyMethod::Local },
        { "0", ProxyMethod::None },
        { "1", ProxyMethod::Socks4 },
        { "2", ProxyMethod::Socks5 },
        { "3", ProxyMethod::Http },
        { "4", ProxyMethod::Telnet },
        { "5", ProxyMethod::Local }
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        ProxyMethod parsed = ProxyMethod::None;
        CHECK_TRUE(ParseProxyMethod(names[i].text, parsed));
        CHECK_TRUE(parsed == names[i].method);
    }
    const char * invalid[] = { "", "socks9", "6", "-1", "http proxy", "None2" };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
    {
        ProxyMethod parsed = ProxyMethod::None;
        CHECK_FALSE(ParseProxyMethod(invalid[i], parsed));
    }
    CHECK_EQ(ProxyMethodName(ProxyMethod::Socks5), "SOCKS5");
    CHECK_EQ(ProxyMethodName(ProxyMethod::Local), "Cmd");
    CHECK_EQ(ProxyMethodName(ProxyMethod::Http), "HTTP");
    CHECK_TRUE(ProxyDefaultPort(ProxyMethod::Socks5) == 1080);
    CHECK_TRUE(ProxyDefaultPort(ProxyMethod::Socks4) == 1080);
    CHECK_TRUE(ProxyDefaultPort(ProxyMethod::Http) == 80);
    CHECK_TRUE(ProxyDefaultPort(ProxyMethod::Telnet) == 23);

    /* The port actually used, and who resolves the destination name: the
     * rule used by this proxy implementation, where SOCKS4 is the one
     * method that cannot take a name. */
    ProxySettings proxy;
    CHECK_FALSE(proxy.Active());
    CHECK_TRUE(proxy.dns == 1);
    proxy.method = ProxyMethod::Socks5;
    CHECK_TRUE(proxy.Active());
    CHECK_TRUE(proxy.EffectivePort() == 1080);
    proxy.port = 3128;
    CHECK_TRUE(proxy.EffectivePort() == 3128);
    CHECK_TRUE(proxy.ResolvesRemotely());
    proxy.method = ProxyMethod::Socks4;
    CHECK_FALSE(proxy.ResolvesRemotely());
    proxy.dns = 2;
    CHECK_TRUE(proxy.ResolvesRemotely());
    proxy.dns = 0;
    CHECK_FALSE(proxy.ResolvesRemotely());

    /* The raw settings, under upstream's names and case-insensitively. */
    ProxySettings settings;
    std::string error;
    CHECK_TRUE(ApplyProxyRawSetting("ProxyMethod", "socks5", settings, error));
    CHECK_TRUE(settings.method == ProxyMethod::Socks5);
    CHECK_TRUE(ApplyProxyRawSetting("proxyhost", " proxy.example.com ",
        settings, error));
    CHECK_EQ(settings.host, "proxy.example.com");
    CHECK_TRUE(ApplyProxyRawSetting("ProxyPort", "3128", settings, error));
    CHECK_TRUE(settings.port == 3128);
    CHECK_TRUE(ApplyProxyRawSetting("ProxyUsername", "proxyuser", settings,
        error));
    CHECK_EQ(settings.userName, "proxyuser");
    CHECK_TRUE(ApplyProxyRawSetting("ProxyDNS", "on", settings, error));
    CHECK_TRUE(settings.dns == 2);
    CHECK_TRUE(ApplyProxyRawSetting("ProxyLocalhost", "1", settings, error));
    CHECK_TRUE(settings.evenLocalhost);
    CHECK_TRUE(ApplyProxyRawSetting("ProxyExcludeList", ".local internal",
        settings, error));
    CHECK_EQ(settings.excludeList, ".local internal");
    CHECK_TRUE(ApplyProxyRawSetting("ProxyLocalCommand", "nc %host %port",
        settings, error));
    CHECK_EQ(settings.command, "nc %host %port");

    /* A password keeps the spaces inside it. */
    ProxySettings spaces;
    CHECK_TRUE(ApplyProxyRawSetting("ProxyPassword", " keep  me ", spaces,
        error));
    CHECK_EQ(spaces.password, "keep  me");

    /* A setting this build does not apply is refused by name, together
     * with the names it does apply: accepting it would be a session that
     * silently ignores part of its own configuration. */
    CHECK_FALSE(ApplyProxyRawSetting("SFTPDownloadQueue", "4", settings,
        error));
    CHECK_TRUE(error.find("SFTPDownloadQueue") != std::string::npos);
    CHECK_TRUE(error.find("ProxyMethod") != std::string::npos);

    /* A value that does not parse is refused with the value named. */
    const char * badValues[] = { "ProxyMethod=carrier-pigeon",
        "ProxyPort=70000", "ProxyPort=0", "ProxyDNS=sometimes",
        "ProxyLocalhost=maybe" };
    for (size_t i = 0; i < sizeof(badValues) / sizeof(badValues[0]); i++)
    {
        const std::string setting = badValues[i];
        const size_t equals = setting.find('=');
        ProxySettings rejected;
        CHECK_FALSE(ApplyProxyRawSetting(setting.substr(0, equals),
            setting.substr(equals + 1), rejected, error));
        CHECK_TRUE(error.find(setting.substr(equals + 1)) != std::string::npos);
    }

    /* An incomplete configuration is refused before a connection. */
    std::string why;
    ProxySettings none;
    CHECK_TRUE(ValidateProxySettings(none, why));
    ProxySettings incomplete;
    incomplete.method = ProxyMethod::Socks5;
    CHECK_FALSE(ValidateProxySettings(incomplete, why));
    CHECK_TRUE(why.find("ProxyHost") != std::string::npos);
    incomplete.host = "proxy.example.com";
    CHECK_TRUE(ValidateProxySettings(incomplete, why));
    ProxySettings telnet;
    telnet.method = ProxyMethod::Telnet;
    telnet.host = "proxy.example.com";
    CHECK_FALSE(ValidateProxySettings(telnet, why));
    CHECK_TRUE(why.find("ProxyTelnetCommand") != std::string::npos);
    telnet.command = "connect %host %port\\n";
    CHECK_TRUE(ValidateProxySettings(telnet, why));
    ProxySettings local;
    local.method = ProxyMethod::Local;
    CHECK_FALSE(ValidateProxySettings(local, why));
    local.command = "nc %host %port";
    CHECK_TRUE(ValidateProxySettings(local, why));

    /* curl speaks SOCKS and HTTP; a telnet or local command proxy has no
     * curl option, and the refusal names the reason instead of connecting
     * around the proxy the session asked for. */
    ProxySettings socks;
    socks.method = ProxyMethod::Socks5;
    socks.host = "proxy.example.com";
    CHECK_TRUE(ProxyUsableByCurl(socks, why));
    ProxySettings http;
    http.method = ProxyMethod::Http;
    http.host = "proxy.example.com";
    CHECK_TRUE(ProxyUsableByCurl(http, why));
    CHECK_FALSE(ProxyUsableByCurl(telnet, why));
    CHECK_TRUE(why.find("curl") != std::string::npos);
    CHECK_FALSE(ProxyUsableByCurl(local, why));
    CHECK_TRUE(ProxyUsableByCurl(none, why));

    /* The settings a session carries reach the options of a connection. */
    SessionOptions options;
    CHECK_FALSE(options.proxy.Active());
    options.proxy = socks;
    CHECK_TRUE(options.proxy.Active());
    CHECK_TRUE(options.proxy == socks);
}

void TestSessionStore()
{
    const std::string temporary = MakeTempDirectory();
    if (temporary.empty())
    {
        return;
    }
    const std::string path = temporary + "/sessions.ini";

    {
        SessionStore store(path);
        CHECK_TRUE(store.Empty());

        StoredSession session;
        session.name = "Servers/web.example.com";
        session.protocol = "sftp";
        session.hostName = "web.example.com";
        session.portNumber = 2222;
        session.userName = "alice";
        session.hostKey = "SHA256:abc";
        session.remoteDirectory = "/srv/www";
        session.localDirectory = "/home/alice/www";
        session.privateKeyFile = "/home/alice/.ssh/id_ed25519";
        std::string error;
        CHECK_TRUE(store.AddOrUpdate(session, error));
        CHECK_TRUE(store.Save(error));
        CHECK_TRUE(!store.Empty());
    }
    {
        SessionStore store(path);
        CHECK_TRUE(store.Sessions().size() == 1);
        const StoredSession * found = store.Find("Servers/web.example.com");
        CHECK_TRUE(found != NULL);
        CHECK_TRUE(found != NULL && found->portNumber == 2222);
        CHECK_TRUE(found != NULL && found->hostKey == "SHA256:abc");
        CHECK_TRUE(found != NULL && found->remoteDirectory == "/srv/www");
        /* Lookup is case-insensitive and finds a bare host name too. */
        CHECK_TRUE(store.Find("SERVERS/WEB.example.com") != NULL);
        CHECK_TRUE(store.Find("web.example.com") != NULL);
        CHECK_TRUE(store.Find("no-such-session") == NULL);

        SessionOptions defaults;
        defaults.portNumber = 22;
        defaults.protocol = "sftp";
        SessionOptions options = SessionStore::ToSessionOptions(*found, defaults);
        CHECK_EQ(options.hostName, "web.example.com");
        CHECK_TRUE(options.portNumber == 2222);
        CHECK_EQ(options.userName, "alice");
        CHECK_EQ(options.initialDirectory, "/srv/www");

        /* 'port=22' on a site of another protocol is what earlier versions
         * wrote for 'no port given', and is read as the protocol's own
         * port; a real port, and the SSH port of an SSH site, are kept. */
        StoredSession legacy;
        legacy.name = "legacy";
        legacy.hostName = "files.example.com";
        legacy.protocol = "ftp";
        legacy.portNumber = 22;
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 21);
        legacy.tls.ftpsMode = 1;
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 990);
        legacy.tls.ftpsMode = 0;
        legacy.protocol = "s3";
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 443);
        legacy.protocol = "webdav";
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 443);
        legacy.protocol = "dav";
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 80);
        legacy.portNumber = 2121;
        legacy.protocol = "ftp";
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 2121);
        legacy.portNumber = 22;
        legacy.protocol = "scp";
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 22);
        legacy.portNumber = 0;
        legacy.protocol = "ftp";
        defaults.portNumber = 2222;
        CHECK_TRUE(SessionStore::ToSessionOptions(legacy, defaults).portNumber == 2222);
        defaults.portNumber = 22;

        /* The connection round-trips back into a session. */
        StoredSession back = SessionStore::FromSessionOptions("copy", options,
            "/srv/www", "/home/alice/www");
        CHECK_EQ(back.hostName, "web.example.com");
        CHECK_EQ(back.userName, "alice");
        CHECK_TRUE(back.lastUsed != 0);

        /* A second session, then export and import. */
        StoredSession second;
        second.name = "backup";
        second.hostName = "backup.example.com";
        second.protocol = "sftp";
        std::string error;
        CHECK_TRUE(store.AddOrUpdate(second, error));
        CHECK_TRUE(store.Save(error));
        CHECK_TRUE(store.Sessions().size() == 2);

        const std::string exported = temporary + "/exported.ini";
        CHECK_TRUE(store.ExportFile(exported, error));

        SessionStore importStore(temporary + "/imported.ini");
        const int imported = importStore.ImportFile(exported, true, error);
        CHECK_TRUE(imported == 2);
        CHECK_TRUE(importStore.Find("backup") != NULL);
        CHECK_TRUE(importStore.Find("Servers/web.example.com") != NULL);

        /* Removing one leaves the other. */
        CHECK_TRUE(store.Remove("backup", error));
        CHECK_TRUE(store.Find("backup") == NULL);
        CHECK_FALSE(store.Remove("backup", error));

        CHECK_TRUE(store.Rename("Servers/web.example.com", "Servers/web2", error));
        CHECK_TRUE(store.Find("Servers/web2") != NULL);
        CHECK_TRUE(store.Save(error));

        SessionStore reread(path);
        CHECK_TRUE(reread.Find("Servers/web2") != NULL);
        CHECK_TRUE(reread.Find("backup") == NULL);
    }

    /*
     * The stored-password format is shared with the graphical client
     * (source/gui/linscp_crypto.py). These vectors were produced by
     * that implementation against key 00..1f and nonce 00..0f: if the
     * construction here ever drifts, decrypting them fails.
     */
    {
        std::string key;
        for (size_t i = 0; i < 32; i++)
        {
            key += static_cast<char>(i);
        }
        std::string plain;
        std::string error;
        const std::string kat1 =
            "lscp1$AAECAwQFBgcICQoLDA0OD3Wb1s8nH47WZ4wX/c56mwbuHDPKIXLzlIBI"
            "SVg1Sd1Trz51POogBQ==";
        const std::string kat2 =
            "lscp1$AAECAwQFBgcICQoLDA0OD26y0chiBtPlC5uzMB+K5Xl4mcJpKa7hN7n"
            "X1ECfqzXFe61r6rb6CDTNrNqVN35FAiSoOPdDUVxNwgMXI+d71V0fqmCVb/6g"
            "CGAd7A==";
        CHECK_TRUE(SessionStore::DecryptPassword(kat1, key, plain, error));
        CHECK_EQ(plain, "kitten2");
        CHECK_TRUE(SessionStore::DecryptPassword(kat2, key, plain, error));
        CHECK_EQ(plain, "p@ss word: with $paces/slashes+plus\nnewline");

        /* Round trip, and no plaintext anywhere near the ciphertext. */
        std::string encoded;
        CHECK_TRUE(SessionStore::EncryptPassword("hunter2!*()", key, encoded,
            error));
        CHECK_TRUE(encoded.compare(0, 6, "lscp1$") == 0);
        CHECK_TRUE(encoded.find("hunter2") == std::string::npos);
        std::string back;
        CHECK_TRUE(SessionStore::DecryptPassword(encoded, key, back, error));
        CHECK_EQ(back, "hunter2!*()");

        /* Tampering and wrong keys are refused, not decoded to garbage.
         * The flip has to land inside the base64 data: the last
         * characters are padding, where 'A' (all zero bits) can decode
         * to exactly the bytes the pad stood for - a 1-in-N chance of
         * a 'tamper' that changes nothing, which showed up as a flaky
         * pair of checks. Mid-string, every flip moves real bits. */
        std::string tampered = encoded;
        const size_t tamperAt = 6 + encoded.size() / 2;
        tampered[tamperAt] =
            tampered[tamperAt] == 'A' ? 'B' : 'A';
        CHECK_FALSE(SessionStore::DecryptPassword(tampered, key, back, error));
        CHECK_TRUE(!error.empty());
        CHECK_FALSE(SessionStore::DecryptPassword(encoded,
            std::string(32, 'x'), back, error));
        CHECK_FALSE(SessionStore::DecryptPassword("no-such-format", key, back,
            error));
        CHECK_FALSE(SessionStore::EncryptPassword(std::string(5000, 'a'), key,
            encoded, error));
    }

    /*
     * On disk: encrypted, under a key file that appears with the first
     * stored password and decrypts again on the next load.
     */
    {
        const std::string secure = temporary + "/secure";
        const std::string ini = secure + "/sessions.ini";
        const std::string keyPath = secure + "/sessions.key";
        SessionStore store(ini);
        CHECK_EQ(store.KeyPath(), keyPath);
        CHECK_FALSE(std::filesystem::exists(keyPath)); /* nothing yet */

        StoredSession session;
        session.name = "vault";
        session.hostName = "vault.example.com";
        session.protocol = "sftp";
        session.password = "correct horse battery staple";
        std::string error;
        CHECK_TRUE(store.AddOrUpdate(session, error));
        CHECK_TRUE(store.Save(error));

        CHECK_TRUE(std::filesystem::exists(keyPath));
        /* The file holds the ciphertext, never the password. */
        FILE * file = fopen(ini.c_str(), "rb");
        CHECK_TRUE(file != NULL);
        std::string content;
        if (file != NULL)
        {
            char buffer[4096];
            size_t got;
            while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
            {
                content.append(buffer, got);
            }
            fclose(file);
        }
        CHECK_TRUE(content.find("correct horse battery staple") ==
            std::string::npos);
        CHECK_TRUE(content.find("password=lscp1$") != std::string::npos);

        /* And a fresh load decrypts it back. */
        SessionStore reread(ini);
        const StoredSession * found = reread.Find("vault");
        CHECK_TRUE(found != NULL);
        CHECK_EQ(found != NULL ? found->password : std::string("missing"),
            "correct horse battery staple");
        CHECK_TRUE(found != NULL && found->passwordRaw.empty());
        CHECK_TRUE(found != NULL && found->passwordError.empty());

        /*
         * Without the key file the entry stays locked: the value is
         * preserved byte for byte across a save, and the reason is
         * reported for whoever tries to use it.
         */
        std::string keyFileContent;
        file = fopen(keyPath.c_str(), "rb");
        CHECK_TRUE(file != NULL);
        if (file != NULL)
        {
            char buffer[512];
            const size_t got = fread(buffer, 1, sizeof(buffer), file);
            keyFileContent.assign(buffer, got);
            fclose(file);
        }
        CHECK_TRUE(remove(keyPath.c_str()) == 0);

        SessionStore locked(ini);
        const StoredSession * held = locked.Find("vault");
        CHECK_TRUE(held != NULL);
        CHECK_TRUE(held != NULL && held->password.empty());
        CHECK_TRUE(held != NULL && held->passwordStored);
        CHECK_TRUE(held != NULL && !held->passwordRaw.empty());
        CHECK_TRUE(held != NULL && !held->passwordError.empty());
        const std::string blob = held != NULL ? held->passwordRaw : "";
        CHECK_TRUE(blob.compare(0, 6, "lscp1$") == 0);
        CHECK_TRUE(locked.Save(error));
        SessionStore afterLockedSave(ini);
        const StoredSession * stillHeld = afterLockedSave.Find("vault");
        CHECK_TRUE(stillHeld != NULL && stillHeld->passwordRaw == blob);
        CHECK_TRUE(stillHeld != NULL && stillHeld->password.empty());

        /* Put the key back and the same value decrypts again. */
        file = fopen(keyPath.c_str(), "wb");
        CHECK_TRUE(file != NULL);
        if (file != NULL)
        {
            fwrite(keyFileContent.data(), 1, keyFileContent.size(), file);
            fclose(file);
        }
        SessionStore restored(ini);
        const StoredSession * back2 = restored.Find("vault");
        CHECK_TRUE(back2 != NULL);
        CHECK_EQ(back2 != NULL ? back2->password : std::string("missing"),
            "correct horse battery staple");
        CHECK_TRUE(back2 != NULL && back2->passwordError.empty());
    }

    /*
     * A plaintext password from before the encryption existed is read,
     * and the next save upgrades it without ever writing it back in
     * the clear.
     */
    {
        const std::string legacyPath = temporary + "/legacy.ini";
        FILE * file = fopen(legacyPath.c_str(), "wb");
        CHECK_TRUE(file != NULL);
        if (file != NULL)
        {
            fputs("[legacy]\nprotocol=sftp\nhost=old.example.com\n"
                "password=hunter2-plain\n", file);
            fclose(file);
        }
        SessionStore legacy(legacyPath);
        const StoredSession * found = legacy.Find("legacy");
        CHECK_TRUE(found != NULL);
        CHECK_EQ(found != NULL ? found->password : std::string("missing"),
            "hunter2-plain");
        std::string error;
        CHECK_TRUE(legacy.Save(error));

        file = fopen(legacyPath.c_str(), "rb");
        std::string content;
        if (file != NULL)
        {
            char buffer[4096];
            size_t got;
            while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
            {
                content.append(buffer, got);
            }
            fclose(file);
        }
        CHECK_TRUE(content.find("hunter2-plain") == std::string::npos);
        CHECK_TRUE(content.find("password=lscp1$") != std::string::npos);

        SessionStore upgraded(legacyPath);
        const StoredSession * again = upgraded.Find("legacy");
        CHECK_EQ(again != NULL ? again->password : std::string("missing"),
            "hunter2-plain");
    }

    /*
     * A stored proxy round-trips with the site: its settings under the keys
     * the graphical client reads too, and its password encrypted like a
     * session password rather than written in the clear.
     */
    {
        const std::string proxiedIni = temporary + "/proxied/sessions.ini";
        const std::string proxiedKey = temporary + "/proxied/sessions.key";
        {
            SessionStore store(proxiedIni);
            StoredSession session;
            session.name = "behind-a-proxy";
            session.protocol = "sftp";
            session.hostName = "files.example.com";
            session.proxy.method = ProxyMethod::Socks5;
            session.proxy.host = "proxy.example.com";
            session.proxy.port = 1080;
            session.proxy.userName = "proxyuser";
            session.proxy.password = "proxy-secret";
            session.proxy.dns = 2;
            session.proxy.evenLocalhost = true;
            session.proxy.excludeList = ".local internal";
            std::string error;
            CHECK_TRUE(store.AddOrUpdate(session, error));
            CHECK_TRUE(store.Save(error));
        }

        FILE * file = fopen(proxiedIni.c_str(), "rb");
        CHECK_TRUE(file != NULL);
        std::string content;
        if (file != NULL)
        {
            char buffer[4096];
            size_t got;
            while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
            {
                content.append(buffer, got);
            }
            fclose(file);
        }
        CHECK_TRUE(content.find("proxy-secret") == std::string::npos);
        CHECK_TRUE(content.find("proxy_method=SOCKS5") != std::string::npos);
        CHECK_TRUE(content.find("proxy_host=proxy.example.com") !=
            std::string::npos);
        CHECK_TRUE(content.find("proxy_password=lscp1$") != std::string::npos);
        CHECK_TRUE(std::filesystem::exists(proxiedKey));

        SessionStore reread(proxiedIni);
        const StoredSession * found = reread.Find("behind-a-proxy");
        CHECK_TRUE(found != NULL);
        CHECK_TRUE(found != NULL && found->proxy.method == ProxyMethod::Socks5);
        CHECK_EQ(found != NULL ? found->proxy.host : std::string("missing"),
            "proxy.example.com");
        CHECK_TRUE(found != NULL && found->proxy.port == 1080);
        CHECK_TRUE(found != NULL && found->proxy.dns == 2);
        CHECK_TRUE(found != NULL && found->proxy.evenLocalhost);
        CHECK_EQ(found != NULL ? found->proxy.excludeList : std::string(),
            ".local internal");
        CHECK_EQ(found != NULL ? found->proxy.password : std::string("missing"),
            "proxy-secret");
        CHECK_TRUE(found != NULL && found->proxyError.empty());

        /* The options of a connection carry the proxy of the site. */
        SessionOptions defaults;
        SessionOptions options =
            SessionStore::ToSessionOptions(*found, defaults);
        CHECK_TRUE(options.proxy.Active());
        CHECK_TRUE(options.proxy.method == ProxyMethod::Socks5);
        CHECK_EQ(options.proxy.password, "proxy-secret");

        /* A site without a proxy stores no proxy keys at all. */
        StoredSession direct = *found;
        direct.name = "direct";
        direct.proxy = ProxySettings();
        std::string error;
        CHECK_TRUE(reread.AddOrUpdate(direct, error));
        CHECK_TRUE(reread.Save(error));
        file = fopen(proxiedIni.c_str(), "rb");
        content.clear();
        if (file != NULL)
        {
            char buffer[8192];
            size_t got;
            while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
            {
                content.append(buffer, got);
            }
            fclose(file);
        }
        const size_t directSection = content.find("[direct]");
        CHECK_TRUE(directSection != std::string::npos);
        CHECK_TRUE(directSection != std::string::npos &&
            content.find("proxy_method", directSection) == std::string::npos);

        /* Without the key file the proxy password stays locked: the
         * ciphertext survives a save and the reason is reported, because a
         * site must not be opened around the proxy it was stored with. */
        CHECK_TRUE(remove(proxiedKey.c_str()) == 0);
        SessionStore withoutKey(proxiedIni);
        const StoredSession * locked = withoutKey.Find("behind-a-proxy");
        CHECK_TRUE(locked != NULL);
        CHECK_TRUE(locked != NULL && locked->proxy.password.empty());
        CHECK_TRUE(locked != NULL && !locked->proxyError.empty());
        const std::string blob = locked != NULL ?
            locked->proxyPasswordRaw : std::string();
        CHECK_TRUE(blob.compare(0, 6, "lscp1$") == 0);
        CHECK_TRUE(withoutKey.Save(error));
        SessionStore afterSave(proxiedIni);
        const StoredSession * stillLocked = afterSave.Find("behind-a-proxy");
        CHECK_TRUE(stillLocked != NULL &&
            stillLocked->proxyPasswordRaw == blob);
    }


    /* Names are validated. */
    CHECK_FALSE(SessionStore::IsValidName(""));
    CHECK_FALSE(SessionStore::IsValidName(" leading"));
    CHECK_FALSE(SessionStore::IsValidName("]"));
    CHECK_FALSE(SessionStore::IsValidName("/leading-slash"));
    CHECK_FALSE(SessionStore::IsValidName("trailing-slash/"));
    CHECK_FALSE(SessionStore::IsValidName("Empty//Segment"));
    CHECK_TRUE(SessionStore::IsValidName("Servers/web1"));
    CHECK_TRUE(SessionStore::IsValidName("Prod/EU/web1"));

    /* Folder hierarchy listing and removal. */
    {
        const std::string folderIni = JoinLocalPath(temporary, "folders.ini");
        SessionStore folderStore(folderIni);
        std::string error;
        StoredSession s1;
        s1.name = "Prod/Web/app1";
        s1.hostName = "app1.example.com";
        StoredSession s2;
        s2.name = "Prod/DB/db1";
        s2.hostName = "db1.example.com";
        StoredSession s3;
        s3.name = "Stage/app";
        s3.hostName = "stage.example.com";
        CHECK_TRUE(folderStore.AddOrUpdate(s1, error));
        CHECK_TRUE(folderStore.AddOrUpdate(s2, error));
        CHECK_TRUE(folderStore.AddOrUpdate(s3, error));
        CHECK_TRUE(folderStore.Folders().size() == 4);
        CHECK_TRUE(folderStore.SessionsInFolder("Prod").size() == 2);
        CHECK_TRUE(folderStore.SessionsInFolder("Prod/Web").size() == 1);
        CHECK_TRUE(folderStore.RemoveFolder("Prod", error) == 2);
        CHECK_TRUE(folderStore.Sessions().size() == 1);
    }

    RemoveTreeQuiet(temporary);
}

/* ------------------------------------------------------------------ *
 * Remote editing                                                      *
 * ------------------------------------------------------------------ */

void TestEditorHelpers()
{
    const char text[] = "hello\nworld";
    CHECK_TRUE(LooksLikeText(text, sizeof(text) - 1));
    const char binary[] = "he\0llo";
    CHECK_TRUE(LooksLikeText(binary, sizeof(binary) - 1) == false);
    CHECK_TRUE(LooksLikeText("", 0));

    std::string error;
    /* A configured editor that does not exist is an error, not a
     * surprise later on. */
    CHECK_TRUE(ResolveEditorCommand("linscp-no-such-editor-xyz", error).empty());
    CHECK_FALSE(error.empty());
    (void)text;
    (void)binary;

    const std::string program = "/bin/echo";
    if (!program.empty())
    {
        const std::vector<std::string> words = ResolveEditorCommand(program, error);
        CHECK_TRUE(!words.empty());
        CHECK_TRUE(error.empty());

        /* An editor command with arguments keeps them. */
        const std::vector<std::string> withArgs =
            ResolveEditorCommand(program + " --wait", error);
        CHECK_TRUE(withArgs.size() == 2);
        CHECK_TRUE(withArgs.size() == 2 && withArgs[1] == "--wait");
    }

    /* The environment decides when nothing is configured. */
    const char * oldEditor = getenv("LINSCP_EDITOR");
    const bool hadEditor = oldEditor != NULL;
    const std::string savedEditor = hadEditor ? oldEditor : "";
    SetEnvVar("LINSCP_EDITOR", "linscp-no-such-editor-xyz");
    CHECK_TRUE(ResolveEditorCommand("", error).empty());
    if (!program.empty())
    {
        SetEnvVar("LINSCP_EDITOR", program.c_str());
        CHECK_TRUE(!ResolveEditorCommand("", error).empty());
    }
    SetEnvVar("LINSCP_EDITOR", hadEditor ? savedEditor.c_str() : NULL);

    /* The temporary copy lives in a private directory. */
    std::string temporary;
    CHECK_TRUE(PrepareEditorTempFile("/etc/nginx/nginx.conf", temporary, error));
    CHECK_FALSE(temporary.empty());
    CHECK_TRUE(temporary.find("nginx.conf") != std::string::npos);
    const std::string directory = LocalDirName(temporary);
    CHECK_TRUE(StatLocal(directory).isDir);
    RemoveLocalFile(temporary, error);
    RemoveLocalDirectory(directory, error);
}

class FakeRemoteEditAccess : public RemoteFileAccess
{
public:
    std::string content;
    unsigned long mtime;
    unsigned uploads;
    bool mutateOnEditorRun;

    FakeRemoteEditAccess(const std::string & initial, unsigned long initialMtime)
        : content(initial), mtime(initialMtime), uploads(0),
          mutateOnEditorRun(false) {}

    virtual int Stat(const std::string & path, LscpAttrs & attrs,
        std::string & error)
    {
        (void)path;
        error.clear();
        attrs = {};
        attrs.flags = LSCP_ATTR_SIZE | LSCP_ATTR_PERMISSIONS | LSCP_ATTR_ACMODTIME;
        attrs.size = content.size();
        attrs.permissions = 0100644;
        attrs.mtime = mtime;
        attrs.atime = mtime;
        return LSCP_SFTP_STAT_EXISTS;
    }

    virtual int Download(const std::string & remote, const std::string & local,
        bool preserveTime, std::string & error)
    {
        (void)remote;
        (void)preserveTime;
        error.clear();
        FILE * f = fopen(local.c_str(), "wb");
        if (f == NULL)
        {
            error = "cannot write local copy";
            return -1;
        }
        if (!content.empty())
        {
            fwrite(content.data(), 1, content.size(), f);
        }
        fclose(f);
        return 0;
    }

    virtual int Upload(const std::string & local, const std::string & remote,
        bool preserveTime, std::string & error)
    {
        (void)remote;
        (void)preserveTime;
        error.clear();
        FILE * f = fopen(local.c_str(), "rb");
        if (f == NULL)
        {
            error = "cannot read local copy";
            return -1;
        }
        content.clear();
        char buf[4096];
        size_t got = 0;
        while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
        {
            content.append(buf, got);
        }
        fclose(f);
        mtime++;
        uploads++;
        return 0;
    }
};

void TestRemoteEditor()
{
    /* UTF-8 BOM and CRLF/LF normalization across remote edit roundtrips. */
    const std::string bomCrlf = "\xEF\xBB\xBFline1\r\nline2\r\n";
    const std::string editedLf = "line1-mod\nline2\n";
    CHECK_EQ(NormalizeEditedText(bomCrlf, editedLf, "preserve"),
        std::string("\xEF\xBB\xBFline1-mod\r\nline2\r\n"));
    CHECK_EQ(NormalizeEditedText(bomCrlf, editedLf, "lf"),
        std::string("\xEF\xBB\xBFline1-mod\nline2\n"));
    CHECK_EQ(NormalizeEditedText("a\nb\n", "a\nb\n", "crlf"),
        std::string("a\r\nb\r\n"));

    const std::string tempDir = MakeTempDirectory();
    if (tempDir.empty())
    {
        return;
    }
    const std::string editorScript = JoinLocalPath(tempDir, "editor.sh");
    {
        FILE * f = fopen(editorScript.c_str(), "wb");
        CHECK_TRUE(f != NULL);
        if (f != NULL)
        {
            fputs("#!/bin/sh\nprintf 'updated line 1\\nupdated line 2\\n' > \"$1\"\n", f);
            fclose(f);
            chmod(editorScript.c_str(), 0700);
        }
    }

    /* Round-trip edit with UTF-8 BOM + CRLF preserved. */
    FakeRemoteEditAccess access(bomCrlf, 1700000000UL);
    RemoteEditor editor(access, NULL);
    EditOptions options;
    options.editor = editorScript;
    std::string error;
    CHECK_TRUE(editor.Edit("/etc/app.conf", options, false, error));
    CHECK_TRUE(access.uploads == 1u);
    CHECK_EQ(access.content,
        std::string("\xEF\xBB\xBFupdated line 1\r\nupdated line 2\r\n"));

    /* Binary file is refused unless -force or -binary is set. */
    FakeRemoteEditAccess binAccess(std::string("abc\0def", 7), 1700000000UL);
    RemoteEditor binEditor(binAccess, NULL);
    CHECK_FALSE(binEditor.Edit("/bin/blob", options, false, error));
    CHECK_TRUE(error.find("text file") != std::string::npos);

    /* Monitoring mode (-monitor) detects a background save after the
     * editor exits and uploads it safely. */
    const std::string monitorScript = JoinLocalPath(tempDir, "monitor-editor.sh");
    {
        FILE * f = fopen(monitorScript.c_str(), "wb");
        CHECK_TRUE(f != NULL);
        if (f != NULL)
        {
            fputs("#!/bin/sh\n"
                  "(sleep 0.08; printf 'monitored-save\\n' > \"$1\") &\n"
                  "exit 0\n", f);
            fclose(f);
            chmod(monitorScript.c_str(), 0700);
        }
    }
    FakeRemoteEditAccess monAccess("initial\n", 1700000000UL);
    RemoteEditor monEditor(monAccess, NULL);
    EditOptions monOptions;
    monOptions.editor = monitorScript;
    monOptions.monitor = true;
    monOptions.monitorPasses = 1;
    monOptions.monitorIntervalMs = 30;
    CHECK_TRUE(monEditor.Edit("/etc/monitored.conf", monOptions, false, error));
    CHECK_TRUE(monAccess.uploads == 1u);
    CHECK_EQ(monAccess.content, std::string("monitored-save\n"));

    RemoveTreeQuiet(tempDir);
}

void TestS3ObjectSettings()
{
    SessionOptions options;
    options.protocol = "s3";
    std::string error;

    CHECK_TRUE(ApplySessionRawSetting("S3StorageClass", "standard_ia",
        options, error));
    CHECK_EQ(options.s3.storageClass, std::string("STANDARD_IA"));
    CHECK_FALSE(ApplySessionRawSetting("S3StorageClass", "NOT_A_CLASS",
        options, error));

    CHECK_TRUE(ApplySessionRawSetting("S3Acl", "bucket-owner-full-control",
        options, error));
    CHECK_EQ(options.s3.acl, std::string("bucket-owner-full-control"));
    CHECK_FALSE(ApplySessionRawSetting("S3Acl", "world-writable",
        options, error));

    CHECK_TRUE(ApplySessionRawSetting("S3ServerSideEncryption", "AES256",
        options, error));
    CHECK_EQ(options.s3.serverSideEncryption, std::string("AES256"));
    options.s3.kmsKeyId = "alias/my-key";
    CHECK_FALSE(ValidateSessionSettings(options, error));
    CHECK_TRUE(ApplySessionRawSetting("S3ServerSideEncryption", "aws:kms",
        options, error));
    CHECK_TRUE(ValidateSessionSettings(options, error));

    CHECK_TRUE(ApplySessionRawSetting("S3RequestPayer", "requester",
        options, error));
    CHECK_TRUE(options.s3.requestPayer);
    CHECK_TRUE(ApplySessionRawSetting("S3Metadata",
        "Author=Ada,Project=linscp", options, error));
    CHECK_EQ(options.s3.metadata["author"], std::string("Ada"));
    CHECK_EQ(options.s3.metadata["project"], std::string("linscp"));

    SessionOptions nonS3 = options;
    nonS3.protocol = "sftp";
    CHECK_FALSE(ValidateSessionSettings(nonS3, error));
}

void TestNewScriptCommands()
{
    const std::string temporary = MakeTempDirectory();
    if (temporary.empty())
    {
        return;
    }
    const char * oldConfig = getenv("LINSCP_CONFIG_DIR");
    const bool hadConfig = oldConfig != NULL;
    const std::string savedConfig = hadConfig ? oldConfig : "";
    SetEnvVar("LINSCP_CONFIG_DIR", temporary.c_str());
    Console::Instance().SetBatchMode(false);

    /* The store is reachable through the script engine, and an empty one
     * is reported instead of failing. 'sessions' is the stored-site
     * listing; bare 'session' now follows upstream and needs a
     * connection. */
    Script script;
    CHECK_TRUE(script.ExecuteLine("sessions"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.Sessions().Empty());

    CHECK_TRUE(script.ExecuteLine(
        "savesession demo -host=demo.example.com -username=alice -port=2222"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.Sessions().Find("demo") != NULL);

    CHECK_TRUE(script.ExecuteLine("rmsession demo"));
    CHECK_TRUE(script.ErrorCount() == 0);
    CHECK_TRUE(script.Sessions().Find("demo") == NULL);

    /* Unknown switches and missing names fail explicitly. */
    CHECK_TRUE(script.ExecuteLine("savesession demo -nonsense=1"));
    CHECK_TRUE(script.ErrorCount() == 1);
    CHECK_TRUE(script.ExecuteLine("savesession demo"));
    CHECK_TRUE(script.ErrorCount() == 2);
    CHECK_TRUE(script.ExecuteLine("rmsession"));
    CHECK_TRUE(script.ErrorCount() == 3);
    CHECK_TRUE(script.ExecuteLine("rmsession no-such-session"));
    CHECK_TRUE(script.ErrorCount() == 4);

    /* 'edit' and 'keepuptodate' need a connection and say so. */
    CHECK_TRUE(script.ExecuteLine("edit /tmp/file.txt"));
    CHECK_TRUE(script.ErrorCount() == 5);
    CHECK_TRUE(script.ExecuteLine("keepuptodate /tmp /tmp"));
    CHECK_TRUE(script.ErrorCount() == 6);

    /* The editor is configurable and reported back. */
    CHECK_TRUE(script.ExecuteLine("option editor vim"));
    CHECK_TRUE(script.ErrorCount() == 6);
    CHECK_TRUE(script.ExecuteLine("option editor"));
    CHECK_TRUE(script.ExecuteLine("option editmaxsize 1000"));
    CHECK_TRUE(script.ExecuteLine("option editmaxsize"));
    CHECK_TRUE(script.ErrorCount() == 6);
    CHECK_TRUE(script.ExecuteLine("option editmaxsize abc"));
    CHECK_TRUE(script.ErrorCount() == 7);

    /* Synchronization validates before it connects, and 'both -delete'
     * is accepted now that the recorded state decides what is obsolete. */
    CHECK_TRUE(script.ExecuteLine("synchronize both -delete /tmp /tmp"));
    CHECK_TRUE(script.ErrorCount() == 8);
    CHECK_TRUE(script.ExecuteLine("synchronize local -criteria=whenever"));
    CHECK_TRUE(script.ErrorCount() == 9);
    CHECK_TRUE(script.ExecuteLine("synchronize local -filemask=sub/*"));
    CHECK_TRUE(script.ErrorCount() == 10);
    CHECK_TRUE(script.ExecuteLine("synchronize local -unknown"));
    CHECK_TRUE(script.ErrorCount() == 11);

    SetEnvVar("LINSCP_CONFIG_DIR", hadConfig ? savedConfig.c_str() : NULL);
    RemoveTreeQuiet(temporary);
}


std::string ModeString(unsigned long mode)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%04lo", static_cast<unsigned long>(mode));
    return std::string(buffer);
}

/* 'chmod' understands octal numbers and symbolic expressions alike. */
void TestPermissionModes()
{
    unsigned long mode = 0;
    std::string error;

    CHECK_TRUE(ParseOctalMode("644", mode));
    CHECK_EQ(ModeString(mode), std::string("0644"));
    CHECK_TRUE(ParseOctalMode("0600", mode));
    CHECK_EQ(ModeString(mode), std::string("0600"));
    CHECK_TRUE(ParseOctalMode("1777", mode));
    CHECK_EQ(ModeString(mode), std::string("1777"));
    CHECK_FALSE(ParseOctalMode("999", mode));
    CHECK_FALSE(ParseOctalMode("", mode));
    CHECK_FALSE(ParseOctalMode("12345", mode));
    CHECK_FALSE(ParseOctalMode("64x", mode));

    /* symbolic clauses, applied to a mode the file already has */
    CHECK_TRUE(ParsePermissions("u+x", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0744"));
    CHECK_TRUE(ParsePermissions("go-w", 0666, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0644"));
    CHECK_TRUE(ParsePermissions("a=r,go-w", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0444"));
    CHECK_TRUE(ParsePermissions("u=rw", 0755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0655"));
    CHECK_TRUE(ParsePermissions("a=rwx", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0777"));
    /* copying one class from another */
    CHECK_TRUE(ParsePermissions("u=g", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0444"));
    CHECK_TRUE(ParsePermissions("g=o,u=r", 0604, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0444"));
    /* the special bits */
    CHECK_TRUE(ParsePermissions("u+s", 0755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("4755"));
    CHECK_TRUE(ParsePermissions("g-s", 02644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0644"));
    CHECK_TRUE(ParsePermissions("a-s", 06755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0755"));
    CHECK_TRUE(ParsePermissions("a+t", 0755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("1755"));
    CHECK_TRUE(ParsePermissions("a-t", 01755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0755"));

    /* '=' clears the whole class it names, its special bit included, and
     * an empty list after '=' is a valid mode that clears the class. Both
     * are chmod(1) behaviour: 'u=rw' on a 4755 file leaves 655, not 4655,
     * and 'u=' is the same clear with nothing set again. The expected
     * values here and below were checked against chmod(1). */
    CHECK_TRUE(ParsePermissions("u=rw", 04755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0655"));
    CHECK_TRUE(ParsePermissions("u=r", 06755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("2455"));
    CHECK_TRUE(ParsePermissions("g=r", 06755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("4745"));
    CHECK_TRUE(ParsePermissions("o=r", 06755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("6754"));
    CHECK_TRUE(ParsePermissions("u=", 04755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0055"));
    CHECK_TRUE(ParsePermissions("g=", 02755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0705"));
    CHECK_TRUE(ParsePermissions("o=", 01755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0750"));
    CHECK_TRUE(ParsePermissions("a=", 07755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0000"));
    CHECK_TRUE(ParsePermissions("=", 04755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0000"));
    /* '=' with nothing after it, then another operator group: the 'who'
     * letters stay in force for the groups of the same clause. */
    CHECK_TRUE(ParsePermissions("u=-w", 04755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0055"));
    /* 's' and 't' are independent: 'o=st' clears the others' rwx and
     * sticky, then sets sticky again, as chmod(1) does. */
    CHECK_TRUE(ParsePermissions("o=st", 01755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("1750"));
    CHECK_TRUE(ParsePermissions("a=st", 01755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("7000"));
    CHECK_TRUE(ParsePermissions("o=s", 01755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0750"));
    /* A copy letter copies rwx only; the setuid bit is not the owner's
     * class as far as copying goes, and is left alone by a 'g=' clause. */
    CHECK_TRUE(ParsePermissions("g=u", 04755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("4775"));
    CHECK_TRUE(ParsePermissions("u=t", 04755, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0055"));
    /* ...and the empty list is still not a mode after '+' or '-'. */
    CHECK_FALSE(ParsePermissions("u+", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions("u-", 0644, false, mode, error));

    /* 'X' means exec where there already is exec, and always for a
     * directory. */
    CHECK_TRUE(ParsePermissions("a+X", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0644"));
    CHECK_TRUE(ParsePermissions("a+X", 0744, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0755"));
    CHECK_TRUE(ParsePermissions("a+X", 0644, true, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0755"));

    /* Several operator groups in one clause apply left to right, the way
     * chmod(1) applies them and the way the graphical client applies them
     * to a local file: reading only the first left the rest to be refused
     * as an unknown permission letter, so the panel accepted a mode the
     * remote chmod then rejected. */
    CHECK_TRUE(ParsePermissions("u+x-w", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0544"));
    CHECK_TRUE(ParsePermissions("g+w+r", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0664"));
    CHECK_TRUE(ParsePermissions("a=r-w", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0444"));
    /* The who letters are read case insensitively, the permission letters
     * are not: 'X' is not 'x'. */
    CHECK_TRUE(ParsePermissions("UG+X", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0644"));
    CHECK_TRUE(ParsePermissions("UG+X", 0744, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0754"));
    /* An octal mode may carry one leading zero, which is how '00644'
     * reaches the client from a script that pads its modes. */
    CHECK_TRUE(ParsePermissions("00644", 0000, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0644"));

    /* a bad expression is refused, and the mode is left alone */
    mode = 0600;
    CHECK_FALSE(ParsePermissions("u?x", 0644, false, mode, error));
    CHECK_TRUE(!error.empty());
    CHECK_FALSE(ParsePermissions("u", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions("zzz", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions("u+q", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions("", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions(",", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions(",,", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions("999", 0644, false, mode, error));
    /* '+x' names nobody, so it would change nothing at all: a mode that
     * silently does nothing is refused rather than applied. */
    CHECK_FALSE(ParsePermissions("+x", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions("-w", 0644, false, mode, error));
    CHECK_FALSE(ParsePermissions("u=rwx,x-w", 0644, false, mode, error));
    /* A refused expression leaves the mode at the one the file has. */
    CHECK_EQ(ModeString(mode), std::string("0644"));
    /* clauses separated by blanks as well as by commas */
    CHECK_TRUE(ParsePermissions("u=rw g=r o=r", 0777, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0644"));

    /* A later clause reads what an earlier one left behind, the way
     * chmod(1) applies them: 'X' and the u/g/o copy letters used to read
     * the mode the file started with, so 'u+x,g+X' on a 644 file left
     * the group alone (0744) where chmod sets it (0754), and 'u+x,g=u'
     * on a 640 file copied the original owner (0760) instead of the one
     * the first clause made (0770). */
    CHECK_TRUE(ParsePermissions("u+x,g+X", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0754"));
    CHECK_TRUE(ParsePermissions("u+x,g=u", 0640, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0770"));
    CHECK_TRUE(ParsePermissions("u+x,u-X", 0644, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0644"));
    CHECK_TRUE(ParsePermissions("g=u", 0740, false, mode, error));
    CHECK_EQ(ModeString(mode), std::string("0770"));
}

/* Server-controlled numbers and log escaping: a hostile server must not
 * steer the client with an out-of-range reply, and a file name must
 * survive the XML action log intact. */
void TestServerReplyHardening()
{
    int value = 0;
    /* PASV octets are 0..255, ports are 1..65535; anything else - text,
     * emptiness, overflow - is a refused reply, not a data connection. */
    CHECK_TRUE(ParseFtpReplyNumber("0", 0, 255, value));
    CHECK_EQ(std::to_string(value), std::string("0"));
    CHECK_TRUE(ParseFtpReplyNumber("255", 0, 255, value));
    CHECK_EQ(std::to_string(value), std::string("255"));
    CHECK_TRUE(ParseFtpReplyNumber("21", 1, 65535, value));
    CHECK_EQ(std::to_string(value), std::string("21"));
    CHECK_TRUE(ParseFtpReplyNumber("65535", 1, 65535, value));
    CHECK_EQ(std::to_string(value), std::string("65535"));
    CHECK_FALSE(ParseFtpReplyNumber("", 0, 255, value));
    CHECK_FALSE(ParseFtpReplyNumber("256", 0, 255, value));
    CHECK_FALSE(ParseFtpReplyNumber("999", 0, 255, value));
    CHECK_FALSE(ParseFtpReplyNumber("0", 1, 65535, value));
    CHECK_FALSE(ParseFtpReplyNumber("65536", 1, 65535, value));
    CHECK_FALSE(ParseFtpReplyNumber("99999999999999", 1, 65535, value));
    CHECK_FALSE(ParseFtpReplyNumber("80x", 1, 65535, value));
    CHECK_FALSE(ParseFtpReplyNumber("-1", 0, 255, value));

    /* An HTTP date with impossible numbers is refused, not converted;
     * the header comes from the server, and an unbounded conversion of
     * twenty digits was undefined behaviour. */
    CHECK_TRUE(ParseHttpDate("Tue, 13 Oct 2026 05:21:00 GMT") > 0);
    CHECK_EQ(std::to_string(
        ParseHttpDate("Tue, 99999999999999999999 Oct 2026 05:21:00 GMT")),
        std::string("0"));
    CHECK_EQ(std::to_string(
        ParseHttpDate("Tue, 13 Oct 9999999999 05:21:00 GMT")),
        std::string("0"));
    CHECK_EQ(std::to_string(ParseHttpDate("not a date")), std::string("0"));

    /* The XML log keeps a tab as a tab: it used to write backslash-t,
     * so two different file names logged identically and neither read
     * back. Markup is still escaped and other controls still dropped. */
    CHECK_EQ(Console::EscapeActionText("a\tb"),
        std::string("a\tb"));
    CHECK_EQ(Console::EscapeActionText("a<b>&\"c\""),
        std::string("a&lt;b&gt;&amp;&quot;c&quot;"));
    CHECK_EQ(Console::EscapeActionText("a\x01" "b"),
        std::string("ab"));
    /* The two upstream escapes of the XML log: an attribute value writes
     * a newline as a character reference (a reader would fold a literal
     * one to a space and a 'call' output would lose its lines), element
     * text keeps it, and both drop the carriage return. */
    CHECK_EQ(Console::EscapeXmlAttr("a\nb\rc"),
        std::string("a&#10;bc"));
    CHECK_EQ(Console::EscapeXmlText("a\nb\rc"),
        std::string("a\nbc"));
    CHECK_EQ(Console::EscapeXmlText("x <&> \"y\""),
        std::string("x &lt;&amp;&gt; \"y\""));
    /* One timestamp spelling, in UTC with the millisecond field. */
    CHECK_EQ(Console::XmlTimestamp(0),
        std::string("1970-01-01T00:00:00.000Z"));
    CHECK_EQ(Console::XmlTimestamp(1760000000UL),
        std::string("2025-10-09T08:53:20.000Z"));
}

/* The command, option and value tables resolve unambiguous prefixes. */
void TestNameAbbreviations()
{
    std::vector<std::string> names;
    names.push_back("close");
    names.push_back("copyid");
    names.push_back("cp");
    names.push_back("cd");

    std::string matches;
    CHECK_EQ(std::to_string(FindPrefixedName(names, "cp", matches)), std::string("2"));
    CHECK_EQ(std::to_string(FindPrefixedName(names, "CLOSE", matches)), std::string("0"));
    CHECK_EQ(std::to_string(FindPrefixedName(names, "cl", matches)), std::string("0"));
    CHECK_EQ(std::to_string(FindPrefixedName(names, "co", matches)), std::string("1"));
    /* 'c' could be close, copyid, cp or cd */
    CHECK_EQ(std::to_string(FindPrefixedName(names, "c", matches)),
        std::to_string(kNameAmbiguous));
    CHECK_EQ(matches, std::string("close, copyid, cp, cd"));
    CHECK_EQ(std::to_string(FindPrefixedName(names, "z", matches)),
        std::to_string(kNameNoMatch));
    CHECK_EQ(matches, std::string(""));
    /* an empty name never resolves, and a prefix longer than a name is no
     * match either */
    CHECK_EQ(std::to_string(FindPrefixedName(names, "", matches)),
        std::to_string(kNameNoMatch));
    CHECK_EQ(std::to_string(FindPrefixedName(names, "closer", matches)),
        std::to_string(kNameNoMatch));

    std::string ambiguous;
    CHECK_EQ(ResolvePrefixedName(names, "co", ambiguous), std::string("copyid"));
    CHECK_TRUE(ambiguous.empty());
    CHECK_EQ(ResolvePrefixedName(names, "c", ambiguous), std::string(""));
    CHECK_EQ(ambiguous, std::string("close, copyid, cp, cd"));
    CHECK_EQ(ResolvePrefixedName(names, "unknown", ambiguous), std::string(""));
    CHECK_TRUE(ambiguous.empty());
}

/* A local wall-clock time, for the relative-time tests. */
std::time_t MakeLocalTime(int year, int month, int day, int hour)
{
    std::tm tm = {};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    return std::mktime(&tm);
}

std::time_t StartOfDay(std::time_t when)
{
    std::tm tm = {};
    if (!LocalTime(when, tm))
    {
        return 0;
    }
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    return std::mktime(&tm);
}

std::tm NowBrokenDown()
{
    std::tm tm = {};
    const std::time_t now = std::time(NULL);
    LocalTime(now, tm);
    return tm;
}

void TestScriptParameterExpansion()
{
    std::vector<std::string> parameters;
    parameters.push_back("first");
    parameters.push_back("second");
    std::string expanded;
    std::string error;

    CHECK_TRUE(ExpandScriptParameters("get %1% /tmp/%2%", parameters, expanded, error));
    CHECK_EQ(expanded, std::string("get first /tmp/second"));
    /* a parameter that was not given stays in the text, so that the command
     * fails visibly instead of copying to an empty path */
    CHECK_TRUE(ExpandScriptParameters("put %3%", parameters, expanded, error));
    CHECK_EQ(expanded, std::string("put %3%"));
    CHECK_TRUE(ExpandScriptParameters("echo %" , parameters, expanded, error));
    CHECK_EQ(expanded, std::string("echo %"));
    CHECK_TRUE(ExpandScriptParameters("echo 100%", parameters, expanded, error));
    CHECK_EQ(expanded, std::string("echo 100%"));
    /* expansion is not recursive */
    parameters.push_back("%2%");
    CHECK_TRUE(ExpandScriptParameters("echo %3%", parameters, expanded, error));
    CHECK_EQ(expanded, std::string("echo %2%"));
    parameters.pop_back();

    /* an unset variable is left alone, a set one is substituted */
    SetEnvVar("LINSCP_TEST_VARIABLE", "a value");
    CHECK_TRUE(ExpandScriptParameters("echo %LINSCP_TEST_VARIABLE%", parameters,
        expanded, error));
    CHECK_EQ(expanded, std::string("echo a value"));
    SetEnvVar("LINSCP_TEST_VARIABLE", NULL);
    CHECK_TRUE(ExpandScriptParameters("echo %LINSCP_TEST_VARIABLE%", parameters,
        expanded, error));
    CHECK_EQ(expanded, std::string("echo %LINSCP_TEST_VARIABLE%"));

    /* %TIMESTAMP% is yyyymmddhhnnss unless the variable is set */
    CHECK_TRUE(ExpandScriptParameters("echo %TIMESTAMP%", parameters, expanded, error));
    CHECK_EQ(expanded, std::string("echo ") + FormatTimestamp(NowBrokenDown(),
        "yyyymmddhhnnss"));
    SetEnvVar("TIMESTAMP", "fixed");
    CHECK_TRUE(ExpandScriptParameters("echo %TIMESTAMP%", parameters, expanded, error));
    CHECK_EQ(expanded, std::string("echo fixed"));
    SetEnvVar("TIMESTAMP", NULL);

    /* an offset and a format */
    const std::time_t now = std::time(NULL) + 86400;
    std::tm tomorrow = {};
    CHECK_TRUE(LocalTime(now, tomorrow));
    CHECK_TRUE(ExpandScriptParameters("echo %TIMESTAMP+1D#yyyy%", parameters,
        expanded, error));
    CHECK_EQ(expanded, std::string("echo ") + std::to_string(1900 + tomorrow.tm_year));
    /* a placeholder with an offset but no format is a mistake, not text to
     * send to the server */
    CHECK_FALSE(ExpandScriptParameters("echo %TIMESTAMP+1Q%#", parameters, expanded,
        error));
    CHECK_TRUE(!error.empty());
    CHECK_FALSE(ExpandScriptParameters("echo %TIMESTAMP+1Q%", parameters, expanded,
        error));
    CHECK_TRUE(!error.empty());
    /* a variable that only starts with the name is a variable, not a
     * timestamp placeholder */
    SetEnvVar("TIMESTAMP_DIR", "/tmp/stamps");
    CHECK_TRUE(ExpandScriptParameters("echo %TIMESTAMP_DIR%", parameters, expanded,
        error));
    CHECK_EQ(expanded, std::string("echo /tmp/stamps"));
    SetEnvVar("TIMESTAMP_DIR", NULL);
}

void TestTimestampFormatting()
{
    std::tm tm = {};
    tm.tm_year = 2024 - 1900;
    tm.tm_mon = 2;      /* March */
    tm.tm_mday = 7;     /* a Thursday */
    tm.tm_wday = 4;    /* 2024-03-07 was a Thursday */
    tm.tm_hour = 15;
    tm.tm_min = 4;
    tm.tm_sec = 9;

    CHECK_EQ(FormatTimestamp(tm, "yyyymmddhhnnss"), std::string("20240307150409"));
    CHECK_EQ(FormatTimestamp(tm, "yyyy-mm-dd"), std::string("2024-03-07"));
    CHECK_EQ(FormatTimestamp(tm, "yy/d/m"), std::string("24/7/3"));
    CHECK_EQ(FormatTimestamp(tm, "hh:nn"), std::string("15:04"));
    /* without an AM/PM marker 'h' is the 24-hour clock, as in Delphi */
    CHECK_EQ(FormatTimestamp(tm, "h:n:s"), std::string("15:4:9"));
    /* quoted text is literal */
    CHECK_EQ(FormatTimestamp(tm, "hh\"am\""), std::string("15am"));
    CHECK_EQ(FormatTimestamp(tm, "am/pm"), std::string("PM"));
    CHECK_EQ(FormatTimestamp(tm, "a/p"), std::string("P"));
    CHECK_EQ(FormatTimestamp(tm, "h:nn am/pm"), std::string("3:04 PM"));
    tm.tm_hour = 9;
    CHECK_EQ(FormatTimestamp(tm, "am/pm"), std::string("AM"));
    CHECK_EQ(FormatTimestamp(tm, "dddd d mmmm mm mmm"),
        std::string("Thursday 7 March 03 Mar"));
    /* an unknown token is kept, because it may be literal text */
    CHECK_EQ(FormatTimestamp(tm, "yyyyQQ"), std::string("2024QQ"));
}

void TestRelativeTime()
{
    /* The day arithmetic below assumes no DST shift; UTC makes that true. */
    setenv("TZ", "UTC", 1);
    tzset();
    const std::time_t base = MakeLocalTime(2020, 6, 15, 12);   /* noon */
    std::time_t result = 0;
    std::string error;

    CHECK_TRUE(TryRelativeTime("1D", base, false, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(base - 86400));
    CHECK_TRUE(TryRelativeTime("2H", base, true, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(base + 2 * 3600));
    CHECK_TRUE(TryRelativeTime("30N", base, true, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(base + 30 * 60));
    CHECK_TRUE(TryRelativeTime("15S", base, false, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(base - 15));
    /* 'today' and 'yesterday' snap to the start of the day */
    CHECK_TRUE(TryRelativeTime("today", base, false, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(StartOfDay(base)));
    CHECK_TRUE(TryRelativeTime("yesterday", base, false, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(StartOfDay(base) - 86400));
    /* a unit followed by 'S' starts the period instead of counting on */
    CHECK_TRUE(TryRelativeTime("1DS", base, false, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(StartOfDay(base - 86400)));
    /* Noon hides a unit that drops the finer fields: from 12:34:56, an
     * hour or minute offset without 'S' keeps the minutes and seconds,
     * and with 'S' it snaps to the start of that hour or minute. */
    const std::time_t odd = base + 34 * 60 + 56;   /* 12:34:56 */
    CHECK_TRUE(TryRelativeTime("2H", odd, true, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(odd + 2 * 3600));
    CHECK_TRUE(TryRelativeTime("1N", odd, true, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(odd + 60));
    CHECK_TRUE(TryRelativeTime("15S", odd, false, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(odd - 15));
    CHECK_TRUE(TryRelativeTime("2HS", odd, true, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(base + 2 * 3600));
    CHECK_TRUE(TryRelativeTime("1NS", odd, true, result, error));
    CHECK_EQ(std::to_string(result), std::to_string(base + 35 * 60));
    /* months and weeks are deliberately not units: upstream reserves 'M'
     * and 'K'/'G' for sizes, and supports S, N, H, D and Y only. */
    CHECK_FALSE(TryRelativeTime("1WS", base, false, result, error));
    CHECK_FALSE(TryRelativeTime("1M", base, false, result, error));
    CHECK_FALSE(TryRelativeTime("1Q", base, false, result, error));
    CHECK_FALSE(TryRelativeTime("many", base, false, result, error));
    CHECK_FALSE(TryRelativeTime("", base, false, result, error));
}

} // namespace

/*
 * The FTP and TLS session settings: upstream's names and vocabulary, the
 * defaults a connection would use without them, and the refusals that stop
 * a setting from being silently dropped.
 */
void TestFtpPassiveReplyParsing()
{
    int port = -1;
    CHECK_TRUE(FtpClient::ParseEpsvReply(
        "229 Entering Extended Passive Mode (|||6446|)", port));
    CHECK_TRUE(port == 6446);
    CHECK_TRUE(FtpClient::ParseEpsvReply(
        "229 Entering Extended Passive Mode (!!!21!)", port));
    CHECK_TRUE(port == 21);
    CHECK_TRUE(FtpClient::ParseEpsvReply(
        "229 Entering Extended Passive Mode (|||65535|)", port));
    CHECK_TRUE(port == 65535);

    const char * badEpsv[] = {
        "229 Entering Extended Passive Mode",
        "229 Entering Extended Passive Mode (||6446|)",
        "229 Entering Extended Passive Mode (|||0|)",
        "229 Entering Extended Passive Mode (|||65536|)",
        "229 Entering Extended Passive Mode (|||999999999999|)",
        "229 Entering Extended Passive Mode (|||64x6|)",
        "229 Entering Extended Passive Mode (|||6446||)",
        "229 Entering Extended Passive Mode (|||6446)",
        "229 Entering Extended Passive Mode (|||64,46|)"
    };
    for (size_t i = 0; i < sizeof(badEpsv) / sizeof(badEpsv[0]); i++)
    {
        port = -1;
        CHECK_FALSE(FtpClient::ParseEpsvReply(badEpsv[i], port));
        CHECK_TRUE(port == 0);
    }

    std::string address;
    port = -1;
    CHECK_TRUE(FtpClient::ParsePasvReply(
        "227 Entering Passive Mode (192,0,2,1,7,138).", address, port));
    CHECK_EQ(address, std::string("192.0.2.1"));
    CHECK_TRUE(port == 1930);
    CHECK_TRUE(FtpClient::ParsePasvReply(
        "227 Entering Passive Mode (127, 0, 0, 1, 195, 80)",
        address, port));
    CHECK_EQ(address, std::string("127.0.0.1"));
    CHECK_TRUE(port == 50000);

    const char * badPasv[] = {
        "227 Entering Passive Mode",
        "227 Entering Passive Mode (256,0,0,1,7,138)",
        "227 Entering Passive Mode (-1,0,0,1,7,138)",
        "227 Entering Passive Mode (1,2,3,4,5)",
        "227 Entering Passive Mode (1,2,3,4,5,6,7)",
        "227 Entering Passive Mode (1,2,3,4,0,0)",
        "227 Entering Passive Mode (1,2,3,4,0,256)",
        "227 Entering Passive Mode (1,2,3,4,9999,6)",
        "227 Entering Passive Mode (1,2,x,4,5,6)",
        "227 Entering Passive Mode (1 2,3,4,5,6)"
    };
    for (size_t i = 0; i < sizeof(badPasv) / sizeof(badPasv[0]); i++)
    {
        address = "stale";
        port = -1;
        CHECK_FALSE(FtpClient::ParsePasvReply(badPasv[i], address, port));
        CHECK_TRUE(address.empty());
        CHECK_TRUE(port == 0);
    }

    /* Which addresses a PASV reply may steer the data connection to.
     * FtpForcePasvIp=1 (the default) replaces an unroutable address with
     * the one the control connection reached. '0,0,0,0' is the one that
     * matters in practice: several servers answer it to mean 'the host of
     * the control connection' (Python's ftplib reads it the same way), and
     * on Linux connecting to 0.0.0.0 reaches this machine's own loopback,
     * so a transfer to a remote server failed as if nothing were listening
     * on the server's own machine. */
    const char * unroutable[] = {
        "0.0.0.0", "0.1.2.3", "10.0.0.1", "127.0.0.1", "169.254.1.1",
        "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1",
        "100.127.255.255"
    };
    for (size_t i = 0; i < sizeof(unroutable) / sizeof(unroutable[0]); i++)
    {
        CHECK_TRUE(FtpClient::IsUnroutablePasvAddress(unroutable[i]));
    }
    const char * routable[] = {
        "8.8.8.8", "1.2.3.4", "172.32.0.1", "100.128.0.1", "192.169.1.1",
        "11.0.0.1", "172.15.255.1", "255.255.255.255"
    };
    for (size_t i = 0; i < sizeof(routable) / sizeof(routable[0]); i++)
    {
        CHECK_FALSE(FtpClient::IsUnroutablePasvAddress(routable[i]));
    }
    /* Not a dotted quad: nothing to say it is unroutable. */
    CHECK_FALSE(FtpClient::IsUnroutablePasvAddress(""));
    CHECK_FALSE(FtpClient::IsUnroutablePasvAddress("abc"));
    CHECK_FALSE(FtpClient::IsUnroutablePasvAddress("1.2.3"));
    CHECK_FALSE(FtpClient::IsUnroutablePasvAddress("1.2.3.4.5"));
    CHECK_FALSE(FtpClient::IsUnroutablePasvAddress("1.2.3.256"));
}

void TestFtpAndTlsSettings()
{
    SessionOptions options;
    CHECK_TRUE(options.ftp.passiveMode);
    CHECK_TRUE(options.ftp.forcePasvIp == 1);
    CHECK_TRUE(options.ftp.useMlsd == 1);
    CHECK_TRUE(options.tls.ftpsMode == 0);

    std::string error;

    CHECK_TRUE(ApplySessionRawSetting("FtpPasvMode", "0", options, error));
    CHECK_FALSE(options.ftp.passiveMode);
    CHECK_TRUE(ApplySessionRawSetting("FtpPasvMode", "on", options, error));
    CHECK_TRUE(options.ftp.passiveMode);
    CHECK_FALSE(ApplySessionRawSetting("FtpPasvMode", "maybe", options, error));
    CHECK_TRUE(error.find("FtpPasvMode") != std::string::npos);

    CHECK_TRUE(ApplySessionRawSetting("FtpUseMlsd", "2", options, error));
    CHECK_TRUE(options.ftp.useMlsd == 2);
    CHECK_TRUE(ApplySessionRawSetting("FtpUseMlsd", "auto", options, error));
    CHECK_TRUE(options.ftp.useMlsd == 1);
    CHECK_TRUE(ApplySessionRawSetting("FtpForcePasvIp", "0", options, error));
    CHECK_TRUE(options.ftp.forcePasvIp == 0);
    CHECK_FALSE(ApplySessionRawSetting("FtpForcePasvIp", "3", options, error));
    CHECK_TRUE(ApplySessionRawSetting("FtpAccount", "billing", options, error));
    CHECK_EQ(options.ftp.account, std::string("billing"));

    /* Ftps is upstream's TFtps, by number and by name. */
    CHECK_TRUE(ApplySessionRawSetting("Ftps", "1", options, error));
    CHECK_TRUE(options.tls.ftpsMode == 1);
    CHECK_TRUE(ApplySessionRawSetting("Ftps", "explicit", options, error));
    CHECK_TRUE(options.tls.ftpsMode == 2);
    CHECK_TRUE(ApplySessionRawSetting("Ftps", "explicittls", options, error));
    CHECK_TRUE(options.tls.ftpsMode == 3);
    CHECK_TRUE(ApplySessionRawSetting("Ftps", "none", options, error));
    CHECK_TRUE(options.tls.ftpsMode == 0);
    CHECK_FALSE(ApplySessionRawSetting("Ftps", "sometimes", options, error));
    CHECK_TRUE(error.find("Ftps") != std::string::npos);

    /* TLS versions, in the forms people write them. */
    const struct { const char * text; int version; } versions[] = {
        { "1.2", 12 }, { "tls1.2", 12 }, { "TLSv1.3", 13 },
        { "12", 12 }, { "13", 13 }, { "default", 0 }
    };
    for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++)
    {
        SessionOptions scratch;
        CHECK_TRUE(ApplySessionRawSetting("MinTlsVersion", versions[i].text,
            scratch, error));
        CHECK_TRUE(scratch.tls.minVersion == versions[i].version);
    }
    CHECK_FALSE(ApplySessionRawSetting("MinTlsVersion", "1.4", options, error));
    CHECK_FALSE(ApplySessionRawSetting("MaxTlsVersion", "ssl3", options, error));

    CHECK_TRUE(ApplySessionRawSetting("TlsCertificateFile", "/tmp/c.pem",
        options, error));
    CHECK_EQ(options.tls.clientCertificate, std::string("/tmp/c.pem"));
    CHECK_TRUE(ApplySessionRawSetting("CaCertificateFile", "/tmp/ca.pem",
        options, error));
    CHECK_EQ(options.tls.caFile, std::string("/tmp/ca.pem"));
    CHECK_TRUE(ApplySessionRawSetting("PinnedPublicKey",
        "sha256//QrZwbj4VrkV2e93XOdjwfQs7i9h3wJB3Fk0BU07xc5A=", options, error));
    CHECK_EQ(options.tls.pinnedPublicKey,
        std::string("sha256//QrZwbj4VrkV2e93XOdjwfQs7i9h3wJB3Fk0BU07xc5A="));

    /* The proxy names keep working through the same door. */
    CHECK_TRUE(ApplySessionRawSetting("ProxyMethod", "SOCKS5", options, error));
    CHECK_TRUE(options.proxy.method == ProxyMethod::Socks5);
    CHECK_TRUE(ApplySessionRawSetting("ProxyHost", "proxy.example", options,
        error));
    CHECK_EQ(options.proxy.host, std::string("proxy.example"));

    /* An unknown name is refused and the accepted ones are listed. */
    CHECK_FALSE(ApplySessionRawSetting("NoSuchSetting", "1", options, error));
    CHECK_TRUE(error.find("NoSuchSetting") != std::string::npos);
    CHECK_TRUE(error.find("FtpPasvMode") != std::string::npos);
    CHECK_TRUE(IsSessionRawSettingName("ftp_use_mlsd") == false);
    CHECK_TRUE(IsSessionRawSettingName("FtpUseMlsd"));
    CHECK_TRUE(IsSessionRawSettingName("ProxyMethod"));
    CHECK_FALSE(IsSessionRawSettingName("SshHostKey"));

    /* Where a setting lands in a connection. */
    SessionOptions ftps;
    ftps.protocol = "ftp";
    ftps.tls.ftpsMode = 1;
    CHECK_TRUE(SessionUsesImplicitTls(ftps));
    CHECK_TRUE(SessionUsesTls(ftps));
    ftps.tls.ftpsMode = 3;
    CHECK_FALSE(SessionUsesImplicitTls(ftps));
    CHECK_TRUE(SessionUsesTls(ftps));
    ftps.tls.ftpsMode = 0;
    CHECK_FALSE(SessionUsesTls(ftps));
    CHECK_TRUE(SessionDefaultPort("ftp", 0) == 21);
    CHECK_TRUE(SessionDefaultPort("ftp", 1) == 990);
    CHECK_TRUE(SessionDefaultPort("ftps", 0) == 990);
    CHECK_TRUE(SessionDefaultPort("sftp", 0) == 22);

    /* The validations: what would send the session somewhere it did not
     * ask to go is refused before a connection is made. */
    SessionOptions plain;
    plain.protocol = "ftp";
    CHECK_TRUE(ValidateSessionSettings(plain, error));

    SessionOptions tlsOptions;
    tlsOptions.protocol = "ftps";
    tlsOptions.tls.minVersion = 13;
    tlsOptions.tls.maxVersion = 12;
    CHECK_FALSE(ValidateSessionSettings(tlsOptions, error));
    CHECK_TRUE(error.find("MinTlsVersion") != std::string::npos);

    SessionOptions fingerprint;
    fingerprint.protocol = "ftps";
    fingerprint.hostKey = "1f2e3d4c5b6a79887766554433221100ffeeddccbbaa99887766554433221100";
    CHECK_FALSE(ValidateSessionSettings(fingerprint, error));
    CHECK_TRUE(error.find("fingerprint") != std::string::npos);
    fingerprint.hostKey = "*";
    CHECK_TRUE(ValidateSessionSettings(fingerprint, error));

    SessionOptions misplaced;
    misplaced.protocol = "sftp";
    misplaced.tls.caFile = "/tmp/ca.pem";
    CHECK_FALSE(ValidateSessionSettings(misplaced, error));
    misplaced = SessionOptions();
    misplaced.protocol = "sftp";
    misplaced.tls.ftpsMode = 1;
    CHECK_FALSE(ValidateSessionSettings(misplaced, error));

    /* An ftpes:// URL is FTP with explicit TLS, and its port stays 21. */
    SessionOptions explicitUrl;
    CHECK_TRUE(ParseSiteUrl("ftpes://alice@example.com/pub", explicitUrl, error));
    CHECK_EQ(explicitUrl.protocol, std::string("ftp"));
    CHECK_TRUE(explicitUrl.tls.ftpsMode == 3);
    CHECK_TRUE(explicitUrl.portNumber == 21);
    SessionOptions implicitUrl;
    CHECK_TRUE(ParseSiteUrl("ftps://alice@example.com/", implicitUrl, error));
    CHECK_EQ(implicitUrl.protocol, std::string("ftps"));
    CHECK_TRUE(implicitUrl.tls.ftpsMode == 1);
    CHECK_TRUE(implicitUrl.portNumber == 990);
    SessionOptions plainUrl;
    CHECK_TRUE(ParseSiteUrl("ftp://alice@example.com/", plainUrl, error));
    CHECK_TRUE(plainUrl.tls.ftpsMode == 0);
    CHECK_TRUE(plainUrl.portNumber == 21);

    /* A TLS mode set before the URL survives it, which is what makes
     * 'open ftp://host -rawsettings Ftps=1' an implicit-TLS session on
     * the port implicit TLS uses. */
    SessionOptions switched;
    switched.protocol = "ftp";
    CHECK_TRUE(ApplySessionRawSetting("Ftps", "1", switched, error));
    CHECK_TRUE(ParseSiteUrl("ftp://alice@example.com/", switched, error));
    CHECK_TRUE(switched.tls.ftpsMode == 1);
    CHECK_TRUE(switched.portNumber == 990);
    CHECK_TRUE(SessionUsesImplicitTls(switched));
}

/*
 * The SHA-256 host key pin a '-hostkey=' value becomes for curl. The
 * conversion has to accept the forms people paste (hex, OpenSSH's
 * SHA256:base64, curl's sha256//base64) and refuse anything else, because
 * a pin that is silently not applied is worse than no pin.
 */
void TestHostKeyPinConversion()
{
    std::string pin;
    const std::string digest =
        "1f2e3d4c5b6a79887766554433221100ffeeddccbbaa99887766554433221100";
    /* The same 32 bytes in the spelling curl compares against. */
    const std::string base64 = "Hy49TFtqeYh3ZlVEMyIRAP/u3cy7qpmId2ZVRDMiEQA";

    CHECK_TRUE(HostKeySha256(digest, pin));
    CHECK_EQ(pin, base64);
    CHECK_TRUE(HostKeySha256("1f:2e:3d:4c:5b:6a:79:88:77:66:55:44:33:22:11:00:"
        "ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00", pin));
    CHECK_EQ(pin, base64);
    CHECK_TRUE(HostKeySha256("1F2E3D4C5B6A79887766554433221100FFEEDDCCBBAA99887766554433"
        "221100", pin));
    CHECK_EQ(pin, base64);

    /* OpenSSH prints the fingerprint without padding, curl may pass it
     * with padding: both name the same pin. */
    CHECK_TRUE(HostKeySha256("SHA256:" + base64, pin));
    CHECK_EQ(pin, base64);
    CHECK_TRUE(HostKeySha256("SHA256:" + base64 + "=", pin));
    CHECK_EQ(pin, base64);
    CHECK_TRUE(HostKeySha256("sha256//" + base64 + "=", pin));
    CHECK_EQ(pin, base64);

    CHECK_FALSE(HostKeySha256("", pin));
    CHECK_FALSE(HostKeySha256("not a fingerprint", pin));
    CHECK_FALSE(HostKeySha256("SHA256:", pin));
    /* An MD5 pin is a real pin, just not one this conversion produces. */
    CHECK_FALSE(HostKeySha256("MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", pin));
    CHECK_FALSE(HostKeySha256("aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", pin));

    /* The decoder keeps only the bits it has not emitted yet. An
     * accumulator that grew without bound overflowed a signed int on the
     * fifth character of any input, which is undefined behaviour rather
     * than a longer digest - and every real fingerprint is longer than
     * four characters. Padding and a repeated alphabet exercise the same
     * path and have to land on the same pin. */
    CHECK_TRUE(HostKeySha256(base64 + "=", pin));
    CHECK_EQ(pin, base64);
    /* The top of the alphabet, so every six-bit group is all ones: 32
     * bytes of 0xFF, spelled the way OpenSSH prints it and the way curl
     * compares it. */
    const std::string ones = "//////////////////////////////////////////8";
    CHECK_TRUE(HostKeySha256(ones + "=", pin));
    CHECK_EQ(pin, ones);
    CHECK_TRUE(HostKeySha256("SHA256:" + ones, pin));
    CHECK_EQ(pin, ones);
}

/*
 * The WebDAV lock and dead-property pieces that can be checked without a
 * server: the token a LOCK reply carries, the rules a property name
 * follows, and the XML a PROPFIND or PROPPATCH sends. A token that is
 * read wrongly locks a file nobody can release, and a property name that
 * builds invalid XML looks like a server failure.
 */
void TestDavLockAndPropertyXml()
{
    std::string token;

    /* The lockdiscovery body of a LOCK reply, with and without the
     * namespace prefixes a server is free to choose. */
    CHECK_TRUE(DavLockTokenFromXml(
        "<?xml version=\"1.0\"?><D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>"
        "<D:activelock><D:locktoken><D:href>opaquelocktoken:1-2-3</D:href>"
        "</D:locktoken></D:activelock></D:lockdiscovery></D:prop>", token));
    CHECK_EQ(token, std::string("opaquelocktoken:1-2-3"));
    CHECK_TRUE(DavLockTokenFromXml(
        "<prop><lockdiscovery><activelock><locktoken><href>urn:uuid:abc"
        "</href></locktoken></activelock></lockdiscovery></prop>", token));
    CHECK_EQ(token, std::string("urn:uuid:abc"));
    /* A bare token body, which some servers send. */
    CHECK_TRUE(DavLockTokenFromXml("  urn:uuid:bare  ", token));
    CHECK_EQ(token, std::string("urn:uuid:bare"));
    /* No token means the caller has to report a failure: a lock nobody
     * can release is worse than a lock that was not taken. */
    CHECK_FALSE(DavLockTokenFromXml("<prop><lockdiscovery/></prop>", token));
    CHECK_FALSE(DavLockTokenFromXml("", token));

    std::string error;
    CHECK_TRUE(DavValidPropertyName("author", error));
    CHECK_TRUE(DavValidPropertyName("file_name-2.x", error));
    CHECK_FALSE(DavValidPropertyName("", error));
    CHECK_FALSE(DavValidPropertyName("2author", error));
    CHECK_FALSE(DavValidPropertyName("a b", error));
    CHECK_FALSE(DavValidPropertyName("a<b", error));
    CHECK_FALSE(DavValidPropertyName("a/b", error));

    /* The request bodies carry the property in this client's namespace,
     * so a protected DAV: property is never the target. */
    CHECK_TRUE(DavPropertyPropfindBody("author").find(
        "xmlns:lscp=\"urn:linscp:properties\"") != std::string::npos);
    CHECK_TRUE(DavPropertyPropfindBody("author").find(
        "<lscp:author/>") != std::string::npos);
    CHECK_TRUE(DavPropertyUpdateBody("author", "Ada").find(
        "<lscp:author>Ada</lscp:author>") != std::string::npos);
    /* A value is data: markup has to be escaped, or the request would not
     * parse and the property would look refused. */
    CHECK_TRUE(DavPropertyUpdateBody("note", "a & b <c> \"d\"").find(
        "a &amp; b &lt;c&gt; &quot;d&quot;") != std::string::npos);

    /* A PROPFIND answer: the value is the element's text, and an absent
     * element is 'found' false rather than an empty string, because the
     * two mean different things to the user. */
    std::string value;
    bool found = true;
    CHECK_TRUE(DavPropertyValueFromXml(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:lscp=\"urn:linscp:properties\">"
        "<d:response><d:propstat><d:prop><lscp:author>Ada</lscp:author>"
        "</d:prop></d:propstat></d:response></d:multistatus>", "author", value,
        found));
    CHECK_TRUE(found);
    CHECK_EQ(value, std::string("Ada"));
    found = true;
    /* The element is absent: the function reports false and the caller
     * reads 'found' - a property that is not set is an answer about the
     * file, not a failure of the request. */
    CHECK_FALSE(DavPropertyValueFromXml("<d:multistatus xmlns:d=\"DAV:\"/>",
        "author", value, found));
    CHECK_FALSE(found);
    CHECK_EQ(value, std::string(""));
    /* A property set to the empty string is set: the element is there. */
    found = false;
    CHECK_TRUE(DavPropertyValueFromXml(
        "<lscp:author xmlns:lscp=\"urn:linscp:properties\"></lscp:author>",
        "author", value, found));
    CHECK_TRUE(found);
    CHECK_EQ(value, std::string(""));
}

void TestLocalization()
{
    const char * oldValue = std::getenv("LINSCP_LANGUAGE");
    const bool hadValue = oldValue != NULL;
    const std::string saved = oldValue ? oldValue : "";
    setenv("LINSCP_LANGUAGE", "es_MX.UTF-8", 1);
    CHECK_EQ(Texts::DirectoryRead(0), std::string("0 entradas"));
    CHECK_EQ(Texts::DirectoryRead(1), std::string("1 entrada"));
    CHECK_EQ(Texts::DirectoryRead(2), std::string("2 entradas"));
    CHECK_TRUE(Texts::Usage().find("Órdenes:") != std::string::npos);
    CHECK_TRUE(Texts::Usage().find("-command=CMD") != std::string::npos);
    CHECK_TRUE(Texts::Usage().find("{version}") == std::string::npos);
    const std::string fingerprint = "SHA256:abc%n{host}";
    CHECK_TRUE(Texts::HostKeyUnknown("host.example", 22, "ed25519", fingerprint)
        .find("no está guardada") != std::string::npos);
    CHECK_TRUE(Texts::HostKeyMismatch("host.example", 22, "ed25519", fingerprint)
        .find("se rechaza continuar") != std::string::npos);
    const std::string warning = Texts::HostKeyUnexpected("host.example", 22,
        "ed25519", fingerprint, "SHA256:expected");
    CHECK_TRUE(warning.find(fingerprint) != std::string::npos);
    CHECK_TRUE(warning.find("SHA256:expected") != std::string::npos);
    CHECK_TRUE(warning.find("no es la esperada") != std::string::npos);
    CHECK_TRUE(warning.find("se rechaza continuar") != std::string::npos);
    CHECK_EQ(Texts::PasswordPrompt("user", "host"), std::string("Contraseña de user@host: "));
    CHECK_EQ(Texts::Translate("Overwrite remote file '{path}'?", {{"path", "{path}%n"}}),
        std::string("¿Sobrescribir el archivo remoto '{path}%n'?"));
    CHECK_EQ(Texts::Translate(" [y/N]: "), std::string(" [s/N]: "));
    /* German, through a regional locale that falls back to 'de'. Switches
     * stay literal while their metavariables are translated. */
    setenv("LINSCP_LANGUAGE", "de_AT.UTF-8", 1);
    CHECK_EQ(Texts::DirectoryRead(1), std::string("1 Eintrag"));
    CHECK_EQ(Texts::DirectoryRead(2), std::string("2 Einträge"));
    CHECK_TRUE(Texts::Usage().find("Befehle:") != std::string::npos);
    CHECK_TRUE(Texts::Usage().find("-filemask=MASKE") != std::string::npos);
    CHECK_TRUE(Texts::Usage().find("{version}") == std::string::npos);
    CHECK_TRUE(Texts::HostKeyUnknown("host.example", 22, "ed25519", fingerprint)
        .find("nicht zwischengespeichert") != std::string::npos);
    CHECK_EQ(Texts::PasswordPrompt("user", "host"), std::string("Passwort für user@host: "));
    CHECK_EQ(Texts::RemoteError("read", "{path}%n", "x"),
        std::string("Lesen von '{path}%n' nicht möglich. x"));
    CHECK_EQ(Texts::Translate(" [y/N]: "), std::string(" [j/N]: "));
    setenv("LINSCP_LANGUAGE", "unsupported", 1);
    CHECK_EQ(Texts::ConnectionClosed(), std::string("Connection has been unexpectedly closed."));
    setenv("LINSCP_LANGUAGE", "C", 1);
    CHECK_EQ(Texts::DirectoryRead(2), std::string("2 entries"));
    if (hadValue) setenv("LINSCP_LANGUAGE", saved.c_str(), 1);
    else unsetenv("LINSCP_LANGUAGE");
}

void TestNonUnixListingFormats()
{
    /* DOS/IIS listing lines */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseDosListingLine(
            "03-25-23  11:22AM       <DIR>          dirname", entry));
        CHECK_EQ(entry.name, std::string("dirname"));
        CHECK_TRUE(entry.isDir);
        CHECK_TRUE(entry.typeKnown);
        CHECK_TRUE(entry.timeKnown);
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseDosListingLine(
            "07-14-22  04:00PM             12345    filename.txt", entry));
        CHECK_EQ(entry.name, std::string("filename.txt"));
        CHECK_FALSE(entry.isDir);
        CHECK_TRUE(entry.typeKnown);
        CHECK_EQ(std::to_string(entry.size), std::string("12345"));
    }
    /*
     * A server that puts a blank between the time and the meridiem wrote
     * the meridiem into the column where the size belongs. The size came
     * out as zero and the name carried the size in front of it.
     */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseDosListingLine(
            "07-14-22  04:00 PM            12345    filename.txt", entry));
        CHECK_EQ(entry.name, std::string("filename.txt"));
        CHECK_FALSE(entry.isDir);
        CHECK_EQ(std::to_string(entry.size), std::string("12345"));
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseDosListingLine(
            "03-25-23  11:22 PM       <DIR>          dirname", entry));
        CHECK_EQ(entry.name, std::string("dirname"));
        CHECK_TRUE(entry.isDir);
    }
    /* A meridiem in a listing of its own is not a file name. */
    {
        ListingEntry entry;
        CHECK_FALSE(ParseDosListingLine(
            "07-14-22  04:00 PM", entry));
    }
    /* A time that is not a time is not a time. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseDosListingLine(
            "07-14-22  ??:??             12345    filename.txt", entry));
        CHECK_FALSE(entry.timeKnown);
    }
    /* DOS line should not match Unix. */
    {
        ListingEntry entry;
        CHECK_FALSE(ParseUnixListingLine(
            "03-25-23  11:22AM       <DIR>          dirname", entry));
    }
    /* VMS listing lines */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseVmsListingLine(
            "FILE.TXT;1    25  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)",
            entry));
        CHECK_EQ(entry.name, std::string("FILE.TXT"));
        CHECK_FALSE(entry.isDir);
        CHECK_TRUE(entry.typeKnown);
        CHECK_EQ(std::to_string(entry.size), std::string("25"));
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseVmsListingLine(
            "SUBDIR.DIR;1     3  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)",
            entry));
        CHECK_EQ(entry.name, std::string("SUBDIR"));
        CHECK_TRUE(entry.isDir);
        CHECK_TRUE(entry.typeKnown);
    }
    /* ParseAnyListingLine tries all formats */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseAnyListingLine(
            "-rw-r--r-- 1 user group 12345 Jun 25 11:22 test.txt", entry));
        CHECK_EQ(entry.name, std::string("test.txt"));
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseAnyListingLine(
            "03-25-23  11:22AM       <DIR>          dirname", entry));
        CHECK_EQ(entry.name, std::string("dirname"));
        CHECK_TRUE(entry.isDir);
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseAnyListingLine(
            "FILE.TXT;1    25  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)",
            entry));
        CHECK_EQ(entry.name, std::string("FILE.TXT"));
    }
    /* LooksLikeDosListing and LooksLikeVmsListing */
    CHECK_TRUE(LooksLikeDosListing("03-25-23  11:22AM       <DIR>          dir"));
    CHECK_FALSE(LooksLikeDosListing("-rw-r--r-- 1 user group 12345 Jun 25 test"));
    CHECK_TRUE(LooksLikeVmsListing(
        "FILE.TXT;1    25  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)"));
    CHECK_FALSE(LooksLikeVmsListing("-rw-r--r-- 1 user group 12345 Jun 25 test"));

    /* A server that writes its months in lower case is still a VMS
     * server. Detection and parsing have to agree on the case, or the
     * caller is left with a directory it says it could not read. */
    CHECK_TRUE(LooksLikeVmsListing(
        "file.txt;1    25  25-jun-2023 11:22:33 [owner] (rwed,rwed,re,re)"));
    {
        ListingEntry entry;
        CHECK_TRUE(ParseVmsListingLine(
            "file.txt;1    25  25-jun-2023 11:22:33 [owner] (rwed,rwed,re,re)",
            entry));
        CHECK_EQ(entry.name, std::string("file.txt"));
        CHECK_TRUE(entry.timeKnown);
    }

    /* The protection field is the permissions the line actually carries:
     * (RWED,RWED,RE,RE) is system, owner, group and world, so the owner
     * may do anything, the group read and execute, and the world too. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseVmsListingLine(
            "FILE.TXT;1    25  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)",
            entry));
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0100755UL));
        CHECK_EQ(PermissionsString(entry.permissions), std::string("-rwxr-xr-x"));
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseVmsListingLine(
            "SECRET.DAT;1   4  25-JUN-2023 11:22:33 [OWNER] (RWED,RW-,,)",
            entry));
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0100600UL));
        CHECK_EQ(PermissionsString(entry.permissions), std::string("-rw-------"));
    }
    /* A protection field that is not four classes is not guessed from. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseVmsListingLine(
            "ODD.TXT;1    25  25-JUN-2023 11:22:33 [OWNER] (RWED,RWED)", entry));
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0100644UL));
    }
    /* What follows the date has to be a time before it is read as one:
     * letters where digits belong used to become a negative hour that
     * mktime() folded into some other day, reported as a known time. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseVmsListingLine(
            "NOTIME.TXT;1    25  25-JUN-2023 [OWNER] (RWED,RWED,RE,RE)", entry));
        CHECK_EQ(entry.name, std::string("NOTIME.TXT"));
        CHECK_FALSE(entry.timeKnown);
    }
    {
        ListingEntry entry;
        CHECK_FALSE(ParseVmsListingLine(
            "BAD.TXT;1    25  99-XYZ-2023 11:22:33 [OWNER] (RWED,RWED,RE,RE)",
            entry));
    }

    /* A mode has to survive the round trip through both directions. The
     * special bits and the file type are part of what a listing says:
     * losing them made a setuid binary look ordinary and a symbolic link
     * look like the regular file it points at. */
    {
        static const char * const modes[] = {
            "-rwsr-xr-x", "-rwxr-sr-x", "drwxrwxrwt", "-rw-r--r--",
            "drwxr-xr-x", "-rwxrwxrwx", "-r--r--r--", "drwx------"
        };
        for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
        {
            CHECK_EQ(PermissionsString(PermissionsFromString(modes[i])),
                std::string(modes[i]));
        }
    }
    /* An upper-case S or T is the special bit without the execute bit. */
    CHECK_EQ(PermissionsString(PermissionsFromString("-rwSr--r--")),
        std::string("-rwSr--r--"));
    CHECK_EQ(PermissionsString(PermissionsFromString("drwxr-xr-T")),
        std::string("drwxr-xr-T"));

    /* A symbolic link line from any of the three producers: the shared
     * parser takes the target off the name and keeps the link's own type,
     * so no single backend has to know about the arrow. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseUnixListingLine(
            "lrwxrwxrwx 1 user group 11 Jun 25 11:22 link.txt -> hello.txt",
            entry));
        CHECK_EQ(entry.name, std::string("link.txt"));
        CHECK_FALSE(entry.isDir);
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0120777UL));
        CHECK_EQ(PermissionsString(entry.permissions), std::string("lrwxrwxrwx"));
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseAnyListingLine(
            "lrwxrwxrwx 1 user group 4 Jun 25 11:22 odd -> name.txt", entry));
        CHECK_EQ(entry.name, std::string("odd"));
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0120777UL));
    }
    /* A regular file whose name holds the arrow sequence keeps all of it:
     * only a link line has a target to remove. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseUnixListingLine(
            "-rw-r--r-- 1 user group 4 Jun 25 11:22 odd -> name.txt", entry));
        CHECK_EQ(entry.name, std::string("odd -> name.txt"));
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0100644UL));
    }

    /* A character or block device has 'major, minor' in the size column.
     * The extra column shifted the date and the name by one, so the entry
     * was listed as '20:00 null' - a name no 'get', 'rm' or 'cd' could
     * find - and its date was lost. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseUnixListingLine(
            "crw-rw-rw-   1 root root      1,   3 Oct 25 20:00 null", entry));
        CHECK_EQ(entry.name, std::string("null"));
        CHECK_FALSE(entry.isDir);
        CHECK_TRUE(entry.typeKnown);
        CHECK_EQ(std::to_string(entry.size), std::string("0"));
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0020666UL));
        CHECK_TRUE(entry.timeKnown);
    }
    {
        ListingEntry entry;
        CHECK_TRUE(ParseAnyListingLine(
            "brw-rw----   1 root disk    259,   0 Oct 25 20:00 nvme0n1", entry));
        CHECK_EQ(entry.name, std::string("nvme0n1"));
        CHECK_EQ(std::to_string(entry.size), std::string("0"));
        CHECK_EQ(std::to_string(entry.permissions), std::to_string(0060660UL));
        CHECK_TRUE(entry.timeKnown);
    }
    /* A device listed with a year instead of a time. */
    {
        ListingEntry entry;
        CHECK_TRUE(ParseUnixListingLine(
            "crw-rw-rw- 1 root root 1, 3 Jan  1  2020 dev-old", entry));
        CHECK_EQ(entry.name, std::string("dev-old"));
        CHECK_TRUE(entry.timeKnown);
    }
}

void TestEncodingHelpers()
{
    /* UTF-8 BOM detection */
    {
        std::string bom = "\xEF\xBB\xBFhello";
        CHECK_TRUE(HasUtf8Bom(bom));
    }
    {
        std::string noBom = "hello";
        CHECK_FALSE(HasUtf8Bom(noBom));
    }
    /* UTF-8 validation */
    CHECK_TRUE(IsValidUtf8("hello world"));
    CHECK_TRUE(IsValidUtf8("日本語テスト"));
    CHECK_TRUE(IsValidUtf8(std::string("\xEF\xBB\xBF") + "with BOM"));
    CHECK_TRUE(IsValidUtf8(""));
    /* Invalid UTF-8 sequences */
    CHECK_FALSE(IsValidUtf8(std::string("\xC0\x80")));       /* overlong */
    CHECK_FALSE(IsValidUtf8(std::string("\x80")));           /* continuation */
    CHECK_FALSE(IsValidUtf8(std::string("\xFE")));           /* invalid lead */
    /* ConvertToUtf8 / ConvertFromUtf8 round-trip (ISO-8859-1) */
    {
        std::string error;
        std::string latin1 = "caf\xE9";  /* café in ISO-8859-1 */
        std::string utf8 = ConvertToUtf8(latin1, "ISO-8859-1", error);
        CHECK_TRUE(error.empty());
        CHECK_TRUE(!utf8.empty());
        /* The é character should be C3 A9 in UTF-8 */
        CHECK_TRUE(utf8.find("\xC3\xA9") != std::string::npos);
        /* Convert back */
        std::string back = ConvertFromUtf8(utf8, "ISO-8859-1", error);
        CHECK_TRUE(error.empty());
        CHECK_EQ(back, latin1);
    }
    /* Invalid encoding name */
    {
        std::string error;
        std::string result = ConvertToUtf8("test", "INVALID-ENC", error);
        CHECK_TRUE(!error.empty());
    }
}


void TestSshJumpSettings()
{
    SessionOptions options;
    std::string error;
    CHECK_FALSE(options.tunnel.enabled);
    CHECK_TRUE(options.tunnel.portNumber == 22);
    CHECK_TRUE(IsSessionRawSettingName("TunnelHostKey"));
    CHECK_TRUE(ApplySessionRawSetting("tUnNeL", "1", options, error));
    CHECK_FALSE(ValidateSessionSettings(options, error));
    CHECK_TRUE(ApplySessionRawSetting("TunnelHostName", "jump.example", options, error));
    CHECK_TRUE(ValidateSessionSettings(options, error));
    for (const char * protocol : {"sftp", "scp", "ssh", "ftp", "ftps", "dav", "webdav", "s3"})
    {
        options.protocol = protocol;
        CHECK_TRUE(ValidateSessionSettings(options, error));
    }
    options.protocol = "sftp";
    for (const char * host : {"", "two hosts", "host\ncommand", "host\tname"})
    {
        options.tunnel.hostName = host;
        CHECK_FALSE(ValidateSessionSettings(options, error));
    }
    options.tunnel.hostName = "::1";
    CHECK_TRUE(ValidateSessionSettings(options, error));
    for (const char * value : {"0", "-1", "65536", "22x", "99999999999999999999", ""})
    {
        CHECK_FALSE(ApplySessionRawSetting("TunnelPortNumber", value, options, error));
        CHECK_TRUE(options.tunnel.portNumber == 22);
    }
    CHECK_FALSE(ApplySessionRawSetting("Tunnel", "2", options, error));
    CHECK_TRUE(options.tunnel.enabled);
    CHECK_TRUE(ApplySessionRawSetting("TunnelPortNumber", "65535", options, error));
    CHECK_TRUE(ApplySessionRawSetting("TunnelLocalPortNumber", "0", options, error));
    CHECK_TRUE(options.tunnel.localPortNumber == 0);
    CHECK_TRUE(ApplySessionRawSetting("TunnelLocalPortNumber", "8000", options, error));
    CHECK_TRUE(options.tunnel.localPortNumber == 8000);
    CHECK_TRUE(ApplySessionRawSetting("TunnelLocalPortNumber", "0", options, error));
    CHECK_FALSE(ApplySessionRawSetting("TunnelPortFwd", "L8000:host:22", options, error));
    CHECK_TRUE(ApplySessionRawSetting("TunnelPassword", "  secret  ", options, error));
    CHECK_TRUE(ApplySessionRawSetting("TunnelPassphrase", "  passphrase  ", options, error));
    CHECK_EQ(options.tunnel.password, std::string("  secret  "));
    CHECK_EQ(options.tunnel.keyPassphrase, std::string("  passphrase  "));
    CHECK_TRUE(IsSessionRawSettingName("TunnelPasswordPlain"));
    CHECK_TRUE(IsSessionRawSettingName("TunnelPassphrasePlain"));
    CHECK_TRUE(ApplySessionRawSetting("TunnelPasswordPlain", " alias secret ", options, error));
    CHECK_TRUE(ApplySessionRawSetting("TunnelPassphrasePlain", " alias phrase ", options, error));
    CHECK_EQ(options.tunnel.password, std::string(" alias secret "));
    CHECK_EQ(options.tunnel.keyPassphrase, std::string(" alias phrase "));
    StoredSession stored = SessionStore::FromSessionOptions("site", options, "/", "/");
    CHECK_TRUE(stored.tunnel.enabled);
    CHECK_TRUE(stored.tunnel.password.empty());
    CHECK_TRUE(stored.tunnel.keyPassphrase.empty());
    stored.tunnel.password = "saved";
    CHECK_EQ(SessionStore::ToSessionOptions(stored, SessionOptions()).tunnel.password,
        std::string("saved"));
    CHECK_TRUE(ApplySessionRawSetting("Tunnel", "0", options, error));
    options.protocol = "ftp";
    CHECK_TRUE(ValidateSessionSettings(options, error));
}

void TestCurlTunnelArgs()
{
    SessionOptions options;
    std::vector<std::string> args;
    AddCurlTunnelArgs(options, args);
    CHECK_TRUE(args.empty());

    options.tunnelSocksPort = 43123;
    AddCurlTunnelArgs(options, args);
    CHECK_TRUE(args.size() == 4);
    if (args.size() == 4)
    {
        CHECK_EQ(args[0], std::string("--socks5-hostname"));
        CHECK_EQ(args[1], std::string("127.0.0.1:43123"));
        CHECK_EQ(args[2], std::string("--noproxy"));
        CHECK_EQ(args[3], std::string());
    }
}

void TestSocks5Helpers()
{
    std::string host, error;
    int port = 0;
    unsigned char ipv4[] = {5, 1, 0, 1, 127, 0, 0, 1, 0, 80};
    CHECK_TRUE(ParseSocks5ConnectRequest(ipv4, sizeof(ipv4), host, port, error));
    CHECK_EQ(host, std::string("127.0.0.1"));
    CHECK_TRUE(port == 80);
    unsigned char domain[] = {5, 1, 0, 3, 11,
        'e','x','a','m','p','l','e','.','c','o','m', 1, 187};
    CHECK_TRUE(ParseSocks5ConnectRequest(domain, sizeof(domain), host, port, error));
    CHECK_EQ(host, std::string("example.com"));
    CHECK_TRUE(port == 443);
    unsigned char truncated[] = {5, 1, 0, 1, 127};
    CHECK_FALSE(ParseSocks5ConnectRequest(truncated, sizeof(truncated), host, port, error));
    unsigned char bindReq[] = {5, 2, 0, 1, 127, 0, 0, 1, 0, 80};
    CHECK_FALSE(ParseSocks5ConnectRequest(bindReq, sizeof(bindReq), host, port, error));
    std::vector<unsigned char> built;
    CHECK_TRUE(BuildSocks5ConnectRequest("example.com", 443, built, error));
    CHECK_TRUE(ParseSocks5ConnectRequest(built.data(), built.size(), host, port, error));
    CHECK_EQ(host, std::string("example.com"));
    CHECK_TRUE(port == 443);
    CHECK_TRUE(BuildSocks5ConnectRequest("127.0.0.1", 21, built, error));
    CHECK_TRUE(ParseSocks5ConnectRequest(built.data(), built.size(), host, port, error));
    CHECK_EQ(host, std::string("127.0.0.1"));
    CHECK_TRUE(port == 21);
    CHECK_FALSE(BuildSocks5ConnectRequest("*", 80, built, error));
    CHECK_FALSE(BuildSocks5ConnectRequest("example.com", 0, built, error));
}

void TestSshTunnelParsing()
{
    /* Local tunnel */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_TRUE(ParseTunnelSpec("8080:localhost:80", TunnelType::Local,
            tunnel, error));
        CHECK_EQ(std::to_string(tunnel.bindPort), std::string("8080"));
        CHECK_EQ(tunnel.remoteHost, std::string("localhost"));
        CHECK_EQ(std::to_string(tunnel.remotePort), std::string("80"));
    }
    /* Local tunnel with bind address */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_TRUE(ParseTunnelSpec("0.0.0.0:8080:localhost:80", TunnelType::Local,
            tunnel, error));
        CHECK_EQ(tunnel.bindAddress, std::string("0.0.0.0"));
        CHECK_EQ(std::to_string(tunnel.bindPort), std::string("8080"));
    }
    /* Dynamic tunnel */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_TRUE(ParseTunnelSpec("1080", TunnelType::Dynamic,
            tunnel, error));
        CHECK_EQ(std::to_string(tunnel.bindPort), std::string("1080"));
    }
    /* Dynamic tunnel with bind address */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_TRUE(ParseTunnelSpec("0.0.0.0:1080", TunnelType::Dynamic,
            tunnel, error));
        CHECK_EQ(tunnel.bindAddress, std::string("0.0.0.0"));
        CHECK_EQ(std::to_string(tunnel.bindPort), std::string("1080"));
    }
    /* Remote tunnel */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_TRUE(ParseTunnelSpec("9090:localhost:9090", TunnelType::Remote,
            tunnel, error));
        CHECK_EQ(std::to_string(tunnel.bindPort), std::string("9090"));
        CHECK_EQ(tunnel.remoteHost, std::string("localhost"));
        CHECK_EQ(std::to_string(tunnel.remotePort), std::string("9090"));
    }
    /* Invalid: empty */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_FALSE(ParseTunnelSpec("", TunnelType::Local, tunnel, error));
    }
    /* Invalid: port out of range */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_FALSE(ParseTunnelSpec("99999:localhost:80", TunnelType::Local,
            tunnel, error));
    }
    /* Invalid: a port that is not a number at all. Reading one with
     * atoi() turned 'localhost:80x' into 80 and a port far past the
     * range of an int into undefined behaviour rather than an error, so
     * a tunnel could be built for a port nobody asked for. */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_FALSE(ParseTunnelSpec("8080:localhost:80x", TunnelType::Local,
            tunnel, error));
        CHECK_FALSE(error.empty());
    }
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_FALSE(ParseTunnelSpec("http:localhost:80", TunnelType::Local,
            tunnel, error));
    }
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_FALSE(ParseTunnelSpec("99999999999999:localhost:80",
            TunnelType::Local, tunnel, error));
    }
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_FALSE(ParseTunnelSpec("-1:localhost:80", TunnelType::Local,
            tunnel, error));
    }
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_TRUE(ParseTunnelSpec("8080", TunnelType::Dynamic, tunnel, error));
        CHECK_EQ(std::to_string(tunnel.bindPort), std::string("8080"));
        CHECK_FALSE(ParseTunnelSpec("1080x", TunnelType::Dynamic, tunnel,
            error));
    }
    /* The ends of the range are both usable. */
    {
        SshTunnel tunnel;
        std::string error;
        CHECK_TRUE(ParseTunnelSpec("1:localhost:65535", TunnelType::Local,
            tunnel, error));
        CHECK_EQ(std::to_string(tunnel.bindPort), std::string("1"));
        CHECK_EQ(std::to_string(tunnel.remotePort), std::string("65535"));
    }
    /* SSH flags */
    {
        SshTunnel tunnel;
        tunnel.type = TunnelType::Local;
        tunnel.bindPort = 8080;
        tunnel.remoteHost = "localhost";
        tunnel.remotePort = 80;
        CHECK_EQ(TunnelSshFlags(tunnel), std::string("-L 8080:localhost:80"));
    }
    {
        SshTunnel tunnel;
        tunnel.type = TunnelType::Dynamic;
        tunnel.bindAddress = "0.0.0.0";
        tunnel.bindPort = 1080;
        CHECK_EQ(TunnelSshFlags(tunnel), std::string("-D 0.0.0.0:1080"));
    }
    /* ssh_version() does not list optional features. The GSSAPI entry point
     * is present only when the loaded libssh was built with WITH_GSSAPI, and
     * the weak reference keeps the no-GSSAPI build linkable. */
    {
        CHECK_TRUE(IsGssapiSupported() ==
            (ssh_gssapi_set_creds != NULL));
        std::string error;
        SessionOptions options;
        /* Upstream's defaults: gssapi-with-mic on, key exchange and
         * credential delegation off. */
        CHECK_TRUE(options.gssapi.auth);
        CHECK_FALSE(options.gssapi.authKex);
        CHECK_FALSE(options.gssapi.forwardTgt);
        CHECK_TRUE(IsSessionRawSettingName("AuthGSSAPI"));
        CHECK_TRUE(ApplySessionRawSetting("AuthGSSAPI", "0", options, error));
        CHECK_FALSE(options.gssapi.auth);
        /* No key-exchange list while AuthGSSAPIKEX itself is off. */
        CHECK_TRUE(GssapiKeyExchangeList(options).empty());
        CHECK_TRUE(ApplySessionRawSetting("AuthGSSAPI", "1", options, error));
        CHECK_TRUE(ApplySessionRawSetting("AuthGSSAPIKEX", "1", options, error));
        CHECK_TRUE(options.gssapi.authKex);
        CHECK_FALSE(ApplySessionRawSetting("AuthGSSAPIKEX", "yes",
            options, error));
        /* Delegation is only ever on by an explicit 1. */
        CHECK_FALSE(options.gssapi.forwardTgt);
        CHECK_TRUE(ApplySessionRawSetting("GSSAPIFwdTGT", "1", options, error));
        CHECK_TRUE(options.gssapi.forwardTgt);
        CHECK_TRUE(ApplySessionRawSetting("LogicalHostName",
            "files.example.org", options, error));
        CHECK_EQ(options.gssapi.logicalHost, "files.example.org");
        CHECK_FALSE(ApplySessionRawSetting("LogicalHostName",
            "two hosts", options, error));
        /* The list starts with the Kerberos exchanges when this libssh
         * can use them, and a pinned host key suppresses it entirely:
         * a pin must be checked, and GSSAPI key exchange has no key. */
        const std::string kex = GssapiKeyExchangeList(options);
        if (IsGssapiKeyExchangeSupported())
        {
            CHECK_TRUE(kex.rfind("gss-group14-sha256-", 0) == 0);
            CHECK_TRUE(kex.find("curve25519-sha256") != std::string::npos);
        }
        else
        {
            CHECK_TRUE(kex.empty());
        }
        /* AuthGSSAPI controls user authentication; a supported server-auth
         * KEX is independent of that switch. */
        SessionOptions authDisabled;
        authDisabled.gssapi.auth = false;
        authDisabled.gssapi.authKex = true;
        const std::string kexWithoutMic =
            GssapiKeyExchangeList(authDisabled);
        CHECK_TRUE(IsGssapiKeyExchangeSupported() ?
            !kexWithoutMic.empty() : kexWithoutMic.empty());
        SessionOptions kexSettings;
        kexSettings.gssapi.authKex = true;
        std::string settingsError;
        CHECK_TRUE(ValidateSessionSettings(kexSettings, settingsError));
        std::string kexError;
        const bool kexSettingsValid =
            ValidateSessionCapabilities(kexSettings, kexError);
        CHECK_TRUE(IsGssapiKeyExchangeSupported() ? kexSettingsValid :
            (!kexSettingsValid &&
             kexError.find("AuthGSSAPIKEX") != std::string::npos));
        SessionOptions pinnedKexSettings;
        pinnedKexSettings.gssapi.authKex = true;
        pinnedKexSettings.hostKey = "SHA256:abc";
        std::string pinnedSettingsError;
        CHECK_TRUE(ValidateSessionSettings(pinnedKexSettings,
            pinnedSettingsError));
        std::string pinnedKexError;
        CHECK_FALSE(ValidateSessionCapabilities(pinnedKexSettings,
            pinnedKexError));
        CHECK_TRUE(pinnedKexError.find("pinned host key") != std::string::npos);
        options.hostKey = "SHA256:abc";
        CHECK_TRUE(GssapiKeyExchangeList(options).empty());
        options.hostKey = "*";
        CHECK_EQ(GssapiKeyExchangeList(options), kex);
        /* The tunnel local port is a real setting now, range-checked. */
        CHECK_TRUE(ApplySessionRawSetting("TunnelLocalPortNumber", "22222",
            options, error));
        CHECK_EQ(std::to_string(options.tunnel.localPortNumber), "22222");
        CHECK_FALSE(ApplySessionRawSetting("TunnelLocalPortNumber", "65536",
            options, error));
        CHECK_FALSE(ApplySessionRawSetting("TunnelLocalPortNumber", "-1",
            options, error));
    }
}

void TestDavEtagHelpers()
{
    /* DavGetEtag() is a static method on ProtocolClient and needs a
     * server, so the live WebDAV suite covers it. What is checked here is
     * the shape of what a write then sends, because a header a server
     * cannot read is a precondition that is not there. */

    /* An entity tag is quoted in the header that carries it, and the value
     * a user pastes back from 'etag -get' has already lost its quotes to
     * the command splitter: both spellings are stored the same way. */
    CHECK_EQ(DavEntityTag("abc123"), std::string("\"abc123\""));
    CHECK_EQ(DavEntityTag("\"abc123\""), std::string("\"abc123\""));
    CHECK_EQ(DavEntityTag("W/abc123"), std::string("W/\"abc123\""));
    CHECK_EQ(DavEntityTag("W/\"abc123\""), std::string("W/\"abc123\""));
    CHECK_EQ(DavEntityTag("*"), std::string("*"));

    SessionOptions options;
    CHECK_EQ(DavIfHeader(options, "/a.txt"), std::string());

    /* A lock token is a Coded-URL, so the angle brackets are part of it. */
    options.davLocks["/a.txt"] = "opaquelocktoken:1";
    CHECK_EQ(DavIfHeader(options, "/a.txt"),
        std::string("(<opaquelocktoken:1>)"));

    /* A path that is both locked and has a version recorded states both in
     * ONE list: RFC 4918 reads an If header as either no-tag lists or
     * tagged lists and never as both, and every condition of a list has to
     * hold. */
    options.davEtags["/a.txt"].ifMatch = "\"v1\"";
    CHECK_EQ(DavIfHeader(options, "/a.txt"),
        std::string("(<opaquelocktoken:1> [\"v1\"])"));

    options.davLocks.erase("/a.txt");
    CHECK_EQ(DavIfHeader(options, "/a.txt"), std::string("([\"v1\"])"));

    /* '-nomatch=' is If-None-Match, which a condition list spells with the
     * 'Not' in front of the tag. */
    options.davEtags["/a.txt"] = SessionOptions::EtagPrecondition();
    options.davEtags["/a.txt"].ifNoneMatch = "\"v1\"";
    CHECK_EQ(DavIfHeader(options, "/a.txt"), std::string("(Not [\"v1\"])"));

    /* A precondition names the path it was recorded for: a collection's
     * tag does not guard a member, whose own writes move the listing the
     * tag names. */
    options.davEtags["/dir"].ifMatch = "\"v2\"";
    CHECK_EQ(DavIfHeader(options, "/dir/inner.txt"), std::string());
    CHECK_EQ(DavIfHeader(options, "/dir"), std::string("([\"v2\"])"));
    CHECK_EQ(DavIfHeader(options, "/directory.txt"), std::string());

    /* The precondition the session keeps, per path. */
    SessionOptions stored;
    stored.davEtags["/test.txt"].ifMatch = "\"abc123\"";
    CHECK_EQ(stored.davEtags["/test.txt"].ifMatch, std::string("\"abc123\""));
    CHECK_TRUE(stored.davEtags["/test.txt"].ifNoneMatch.empty());
    stored.davEtags["/other.txt"].ifNoneMatch = "\"xyz789\"";
    CHECK_EQ(stored.davEtags["/other.txt"].ifNoneMatch,
        std::string("\"xyz789\""));
    /* Clear by erasing */
    stored.davEtags.erase("/test.txt");
    CHECK_TRUE(stored.davEtags.find("/test.txt") == stored.davEtags.end());
    CHECK_FALSE(stored.davEtags.find("/other.txt") == stored.davEtags.end());
}

void TestScpEngine()
{
    /* A path is one argument on a remote command line, so everything goes
     * inside single quotes; the shell then sees no expansion, no separator
     * and no redirection. The one sequence a POSIX shell cannot be handed
     * inside a single-quoted word is a quote, and it is spelled as: close
     * the word, add an escaped quote, open the word again. */
    const std::string quoteEscape = std::string("'") + "\\" + "'" + "'";
    CHECK_EQ(ScpShellQuote("plain"), std::string("'plain'"));
    CHECK_EQ(ScpShellQuote("sub dir/file name.txt"),
        std::string("'sub dir/file name.txt'"));
    CHECK_EQ(ScpShellQuote("it's"), std::string("'it") + quoteEscape + "s'");
    CHECK_EQ(ScpShellQuote("'"), std::string("'") + quoteEscape + "'");
    CHECK_EQ(ScpShellQuote("''"),
        std::string("'") + quoteEscape + quoteEscape + "'");
    CHECK_EQ(ScpShellQuote("$HOME"), std::string("'$HOME'"));
    CHECK_EQ(ScpShellQuote("a;b|c`d`e"), std::string("'a;b|c`d`e'"));
    CHECK_EQ(ScpShellQuote("*?[]"), std::string("'*?[]'"));
    CHECK_EQ(ScpShellQuote(""), std::string("''"));
    /* A trailing backslash stays inside the quotes, so it quotes nothing. */
    CHECK_EQ(ScpShellQuote("dir\\"), std::string("'dir") + "\\" + "'");

    /* The paths the engine refuses to send, and why. */
    std::string error;
    CHECK_TRUE(ScpValidRemotePath("/srv/site/file.txt", error));
    CHECK_TRUE(error.empty());
    CHECK_TRUE(ScpValidRemotePath("sub dir/it's here.txt", error));
    CHECK_FALSE(ScpValidRemotePath("", error));
    CHECK_TRUE(error.find("empty") != std::string::npos);
    /* A newline cannot be told apart from the end of an 'ls -l' line, so a
     * name holding one is refused instead of being listed as two names. */
    error.clear();
    CHECK_FALSE(ScpValidRemotePath("a\nb", error));
    CHECK_TRUE(error.find("control character") != std::string::npos);
    error.clear();
    CHECK_FALSE(ScpValidRemotePath("tab\there", error));
    CHECK_TRUE(error.find("control character") != std::string::npos);
    error.clear();
    CHECK_FALSE(ScpValidRemotePath(
        std::string("del") + static_cast<char>(0x7f), error));
    CHECK_TRUE(error.find("control character") != std::string::npos);

    /* One line of 'ls -l -a' as an entry. */
    ListingEntry entry;
    CHECK_TRUE(ScpParseListingLine(
        "-rw-r--r-- 1 user group 512 Oct 16 05:33 file.txt", entry));
    CHECK_EQ(entry.name, std::string("file.txt"));
    CHECK_EQ(std::to_string(entry.size), std::string("512"));
    CHECK_FALSE(entry.isDir);
    CHECK_TRUE(entry.typeKnown);
    CHECK_EQ(std::to_string(entry.permissions), std::to_string(0100644UL));
    CHECK_EQ(entry.longname,
        std::string("-rw-r--r-- 1 user group 512 Oct 16 05:33 file.txt"));
    /* A name with spaces is one name: the ninth field keeps them. */
    CHECK_TRUE(ScpParseListingLine(
        "drwxr-xr-x 2 user group 60 Oct 16 05:33 sub dir", entry));
    CHECK_EQ(entry.name, std::string("sub dir"));
    CHECK_TRUE(entry.isDir);
    /* The year form an old file is listed with. */
    CHECK_TRUE(ScpParseListingLine(
        "-rw-r--r-- 1 user group 10 Feb 13  2009 hello.txt", entry));
    CHECK_EQ(entry.name, std::string("hello.txt"));
    CHECK_TRUE(entry.timeKnown);
    /* A symbolic link keeps its own name and its own type bits: the
     * ' -> target' half says where the link points, not what it is called. */
    CHECK_TRUE(ScpParseListingLine(
        "lrwxrwxrwx 1 user group 9 Oct 16 05:33 link.txt -> hello.txt", entry));
    CHECK_EQ(entry.name, std::string("link.txt"));
    CHECK_FALSE(entry.isDir);
    CHECK_EQ(std::to_string(entry.permissions), std::to_string(0120777UL));
    /* What is not an entry: the block count 'ls' prints in front of a
     * directory, the two directory links '-a' adds, and a line the shell
     * printed itself - none of which is a name on the server. */
    CHECK_FALSE(ScpParseListingLine("total 12", entry));
    CHECK_FALSE(ScpParseListingLine(
        "drwxr-xr-x 3 user group 100 Oct 16 05:33 .", entry));
    CHECK_FALSE(ScpParseListingLine(
        "drwxr-xr-x 3 user group 100 Oct 16 05:33 ..", entry));
    CHECK_FALSE(ScpParseListingLine("bash: ls: command not found", entry));
    CHECK_FALSE(ScpParseListingLine("", entry));
    /* A plain file whose name holds the arrow sequence keeps its whole
     * name: only a link line has a target to take off. */
    CHECK_TRUE(ScpParseListingLine(
        "-rw-r--r-- 1 user group 4 Oct 16 05:33 odd -> name.txt", entry));
    CHECK_EQ(entry.name, std::string("odd -> name.txt"));

    /* The header lines of the rcp protocol, as the server writes them. */
    char kind = 0;
    unsigned int mode = 0;
    unsigned long long size = 0;
    std::string name;
    unsigned long mtime = 0;
    unsigned long atime = 0;
    CHECK_TRUE(ScpParseHeaderLine("C0644 512 file.txt", kind, mode, size,
        name, mtime, atime));
    CHECK_EQ(std::string(1, kind), std::string("C"));
    CHECK_EQ(std::to_string(mode), std::to_string(0644));
    CHECK_EQ(std::to_string(size), std::string("512"));
    CHECK_EQ(name, std::string("file.txt"));
    /* The line ends in a newline on the wire, and a name may hold spaces. */
    CHECK_TRUE(ScpParseHeaderLine("C0640 10 my file name.txt\n", kind, mode,
        size, name, mtime, atime));
    CHECK_EQ(std::to_string(mode), std::to_string(0640));
    CHECK_EQ(std::to_string(size), std::string("10"));
    CHECK_EQ(name, std::string("my file name.txt"));
    /* A directory header carries no size, and the protocol still sends the
     * field. */
    CHECK_TRUE(ScpParseHeaderLine("D0755 0 tree\n", kind, mode, size, name,
        mtime, atime));
    CHECK_EQ(std::string(1, kind), std::string("D"));
    CHECK_EQ(std::to_string(size), std::string("0"));
    CHECK_EQ(name, std::string("tree"));
    /* Times come first: 'T<mtime> 0 <atime> 0'. */
    CHECK_TRUE(ScpParseHeaderLine("T1792131060 0 1792131061 0\n", kind, mode,
        size, name, mtime, atime));
    CHECK_EQ(std::string(1, kind), std::string("T"));
    CHECK_EQ(std::to_string(mtime), std::string("1792131060"));
    CHECK_EQ(std::to_string(atime), std::string("1792131061"));
    /* 'E' closes a directory level. */
    CHECK_TRUE(ScpParseHeaderLine("E\n", kind, mode, size, name, mtime, atime));
    CHECK_EQ(std::string(1, kind), std::string("E"));
    /* An error the server reports is its own text, kept verbatim. */
    CHECK_TRUE(ScpParseHeaderLine(
        std::string(1, '\x01') + "scp: /x: No such file or directory\n",
        kind, mode, size, name, mtime, atime));
    CHECK_EQ(std::to_string(static_cast<int>(kind)), std::string("1"));
    CHECK_EQ(name, std::string("scp: /x: No such file or directory"));
    CHECK_TRUE(ScpParseHeaderLine(
        std::string(1, '\x02') + "lost connection", kind, mode, size, name,
        mtime, atime));
    CHECK_EQ(std::to_string(static_cast<int>(kind)), std::string("2"));
    /* What is not a header line: a truncated one, a mode outside the
     * permission bits, a size that is not a number, a kind the protocol has
     * no meaning for. */
    CHECK_FALSE(ScpParseHeaderLine("C0644", kind, mode, size, name, mtime,
        atime));
    CHECK_FALSE(ScpParseHeaderLine("C99999 1 file.txt", kind, mode, size, name,
        mtime, atime));
    CHECK_FALSE(ScpParseHeaderLine("C0644 many file.txt", kind, mode, size,
        name, mtime, atime));
    CHECK_FALSE(ScpParseHeaderLine("Q0644 1 file.txt", kind, mode, size, name,
        mtime, atime));
    CHECK_FALSE(ScpParseHeaderLine("T1792131060\n", kind, mode, size, name,
        mtime, atime));
    CHECK_FALSE(ScpParseHeaderLine("", kind, mode, size, name, mtime, atime));

    /* The lines the sending side writes, byte for byte: a header the server
     * has to guess at is a transfer it refuses or truncates. */
    CHECK_EQ(ScpFileHeaderLine(0644, 512, "file.txt"),
        std::string("C0644 512 file.txt\n"));
    CHECK_EQ(ScpFileHeaderLine(0640, 10, "my file name.txt"),
        std::string("C0640 10 my file name.txt\n"));
    /* Only the permission bits go on the wire; the type bits of a local
     * st_mode would put a five digit mode in front of the size. */
    CHECK_EQ(ScpFileHeaderLine(0100644, 512, "file.txt"),
        std::string("C0644 512 file.txt\n"));
    CHECK_EQ(ScpDirectoryHeaderLine(0755, "tree"),
        std::string("D0755 0 tree\n"));
    CHECK_EQ(ScpDirectoryHeaderLine(0100750, "sub dir"),
        std::string("D0750 0 sub dir\n"));
    /* A zero access time means the same as the modification time, which is
     * what a local file with no separate atime should give the server. */
    CHECK_EQ(ScpTimeHeaderLine(1792131060, 0),
        std::string("T1792131060 0 1792131060 0\n"));
    CHECK_EQ(ScpTimeHeaderLine(1792131060, 1792131061),
        std::string("T1792131060 0 1792131061 0\n"));

    /* 'touch -t' reads the stamp in the server's local time, so the command
     * that carries it asks for UTC and the stamp is the UTC reading of the
     * moment. */
    CHECK_EQ(ScpTouchStamp(0), std::string("197001010000.00"));
    CHECK_EQ(ScpTouchStamp(1000000000), std::string("200109090146.40"));
    CHECK_EQ(ScpTouchStamp(1792131060), std::string("202610160611.00"));

    /* The spellings a shell prints for a path that is not there, so that
     * 'stat' can answer "missing" where the server did answer and "error"
     * where it refused. */
    CHECK_TRUE(ScpSaysMissing(
        "ls: cannot access '/x/nope': No such file or directory"));
    CHECK_TRUE(ScpSaysMissing(
        "ls: cannot access '/x/nope': no such file or directory"));
    CHECK_TRUE(ScpSaysMissing("/x/nope: Not a directory"));
    CHECK_TRUE(ScpSaysMissing("/x/nope does not exist"));
    CHECK_TRUE(ScpSaysMissing("ls: /x/nope: not found"));
    /* A refusal is not a missing path. */
    CHECK_FALSE(ScpSaysMissing(
        "ls: cannot open directory '/x': Permission denied"));
    CHECK_FALSE(ScpSaysMissing(""));

    /*
     * The date columns GNU 'ls --full-time' prints, and the offset they are
     * in. An approximation of a timestamp is a synchronizer that sees every
     * file older than six months as changed, so the exact reading has to
     * survive the trip from the server's listing to the entry.
     */
    CHECK_EQ(std::to_string(ScpParseFullTime("2001-09-09",
        "01:46:40.000000000", "+0000")), std::string("1000000000"));
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-10-16",
        "05:33:07.123456789", "+0200")), std::string("1792121587"));
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-10-16",
        "05:33:07.123456789", "-0700")), std::string("1792153987"));
    /* Half hour zones, and the two shapes the offset arrives in. */
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-10-16", "05:33:07",
        "+05:30")), std::string("1792108987"));
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-10-16", "05:33:07",
        "+0530")), std::string("1792108987"));
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-10-16", "05:33:07", "Z")),
        std::string("1792128787"));
    /* The epoch itself is not a usable timestamp: 0 is what "no time"
     * means to every caller, so a reading that would be 0 says "none". */
    CHECK_EQ(std::to_string(ScpParseFullTime("1970-01-01", "00:00:00",
        "+0000")), std::string("0"));
    /* What is not that shape: a month name from a plain listing, an offset
     * that is not one, a month that does not exist, a time that is not one. */
    CHECK_EQ(std::to_string(ScpParseFullTime("Oct 16", "05:33", "+0000")),
        std::string("0"));
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-10-16", "05:33:07.0",
        "somewhere")), std::string("0"));
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-13-16", "05:33:07.0",
        "+0000")), std::string("0"));
    CHECK_EQ(std::to_string(ScpParseFullTime("2026-10-16", "25:33:07.0",
        "+0000")), std::string("0"));
    CHECK_EQ(std::to_string(ScpParseFullTime("", "", "")), std::string("0"));

    /* And a whole listing line in that shape is an entry whose time is
     * exact, where the same line from a plain 'ls -l' carries a minute. */
    CHECK_TRUE(ScpParseListingLine(
        "-rw-r--r-- 1 user group 512 2001-09-09 01:46:40.000000000 +0000 "
        "file.txt", entry));
    CHECK_EQ(entry.name, std::string("file.txt"));
    CHECK_TRUE(entry.timeKnown);
    CHECK_EQ(std::to_string(entry.mtime), std::string("1000000000"));
    CHECK_EQ(std::to_string(entry.size), std::string("512"));
    CHECK_FALSE(entry.isDir);
    CHECK_TRUE(ScpParseListingLine(
        "drwxr-xr-x 2 user group 60 2001-09-09 01:46:40.000000000 +0000 "
        "sub dir", entry));
    CHECK_EQ(entry.name, std::string("sub dir"));
    CHECK_TRUE(entry.isDir);
    CHECK_EQ(std::to_string(entry.mtime), std::string("1000000000"));

    /* Which sessions this engine serves. */
    SessionOptions options;
    options.protocol = "scp";
    CHECK_TRUE(ScpClient::Handles(options));
    options.protocol = "ssh";
    CHECK_TRUE(ScpClient::Handles(options));
    options.protocol = "SCP";
    CHECK_TRUE(ScpClient::Handles(options));
    options.protocol = "sftp";
    CHECK_FALSE(ScpClient::Handles(options));
    options.protocol = "ftp";
    CHECK_FALSE(ScpClient::Handles(options));
}

void TestScpHeaderNamesCannotTraverse()
{
    /* Upstream issue 2477: a nested rcp header must not be able to turn
     * a server-supplied name into a local path traversal. On Linux a
     * backslash is a legal filename byte, but refusing it too keeps the
     * two clients from accepting different remote names. */
    char kind = 0;
    unsigned int mode = 0;
    unsigned long long size = 0;
    std::string name;
    unsigned long mtime = 0, atime = 0;
    const char * refused[] = { ".", "..", "../evil", "sub/evil",
                              "/etc/passwd", "..\\evil" };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i)
    {
        CHECK_FALSE(ScpParseHeaderLine(
            std::string("C0644 1 ") + refused[i], kind, mode, size, name,
            mtime, atime));
        CHECK_FALSE(ScpParseHeaderLine(
            std::string("D0755 0 ") + refused[i], kind, mode, size, name,
            mtime, atime));
    }
    CHECK_TRUE(ScpParseHeaderLine("C0644 1 safe-name.txt", kind, mode,
                                 size, name, mtime, atime));
    CHECK_EQ(name, std::string("safe-name.txt"));
}

void TestAuditRegressions()
{
    using namespace linscp;

    /* HashUtil: hashing a directory must fail rather than report an empty file. */
    const std::string tempDir = "/tmp/linscp-audit-" +
        std::to_string(static_cast<unsigned long>(getpid()));
    std::string fsErr;
    CHECK_TRUE(CreateLocalDirectoryRecursive(tempDir, fsErr));
    char hex[LSCP_HASH_HEX_SIZE];
    CHECK_TRUE(lscp_hash_file("sha-256", tempDir.c_str(), hex, sizeof(hex)) != 0);

    /* TextMode: lone CR and CRLF both become LF cleanly without corruption. */
    const std::string crPath = tempDir + "/mac.txt";
    FILE * f = fopen(crPath.c_str(), "wb");
    CHECK_TRUE(f != NULL);
    if (f != NULL)
    {
        fwrite("one\rtwo\r\nthree\r", 1, 15, f);
        fclose(f);
    }
    unsigned long long convBytes = 0;
    CHECK_TRUE(ConvertToUnixLineEndings(crPath, convBytes, fsErr));
    CHECK_EQ(std::to_string(convBytes), std::string("14"));
    std::string crlfTemp;
    CHECK_TRUE(MakeCRLFUploadCopy(crPath, crlfTemp, fsErr));
    CHECK_FALSE(crlfTemp.empty());
    remove(crlfTemp.c_str());

    /* PathUtil: trailing standalone backslash in SplitCommands, iterative
     * pathological wildcard matching, and FileMask size/time overflow guards. */
    std::vector<std::string> cmds = SplitCommands("echo a\\");
    CHECK_EQ(std::to_string(cmds.size()), std::string("1"));
    CHECK_EQ(cmds[0], std::string("echo a\\"));
    CHECK_FALSE(MatchesMask(
        "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"));
    FileMask badMask;
    CHECK_FALSE(badMask.Parse("*>=999999999999999999999999", fsErr));
    CHECK_FALSE(badMask.Parse("*>=999999999999999999999999d", fsErr));

    /* Console XML escaping: scrub invalid UTF-8 and UTF-16 surrogates while
     * preserving valid multi-byte UTF-8 and tabs. */
    CHECK_EQ(Console::EscapeXmlText(std::string("ok\t\xc3\xa9") + "\xff" + "\xed\xa0\x80!"),
        std::string("ok\t\xc3\xa9\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd!"));

    /* ListingParse: DOS filenames with spaces, symlinks with ' -> ' inside
     * target, and integer overflow on file sizes. */
    ListingEntry entry;
    CHECK_TRUE(ParseDosListingLine(
        "03-25-23  11:22AM       <DIR>          Program Files (x86)", entry));
    CHECK_TRUE(entry.isDir);
    CHECK_EQ(entry.name, std::string("Program Files (x86)"));
    CHECK_TRUE(ParseDosListingLine(
        "07-14-22  04:00PM             12345    my report final.txt", entry));
    CHECK_FALSE(entry.isDir);
    CHECK_EQ(entry.name, std::string("my report final.txt"));
    CHECK_EQ(std::to_string(entry.size), std::string("12345"));
    CHECK_TRUE(ParseUnixListingLine(
        "lrwxrwxrwx 1 u g 12 Oct 25 12:00 link -> a -> b", entry));
    CHECK_EQ(entry.name, std::string("link"));
    CHECK_FALSE(ParseUnixListingLine(
        "-rw-r--r-- 1 u g 99999999999999999999999999 Oct 25 12:00 huge", entry));

    /* TransferPresets: unset (-3) vs explicit off (-1) vs octal mode. */
    TransferPreset preset;
    CHECK_EQ(std::to_string(preset.permissions), std::string("-3"));
    TransferFlags flags;
    flags.permissions = 0640;
    preset.ApplyTo(flags);
    CHECK_EQ(std::to_string(flags.permissions), std::string(std::to_string(0640)));
    CHECK_TRUE(TransferPresetStore::ParseSetting("permissions", "off", preset, fsErr));
    CHECK_EQ(std::to_string(preset.permissions), std::string("-1"));
    preset.ApplyTo(flags);
    CHECK_EQ(std::to_string(flags.permissions), std::string("-1"));

    /* ParseSiteUrl: s3:// default port 443 and port overflow guard. */
    SessionOptions s3Opts;
    CHECK_TRUE(ParseSiteUrl("s3://mybucket/prefix", s3Opts, fsErr));
    CHECK_EQ(std::to_string(s3Opts.portNumber), std::string("443"));
    CHECK_FALSE(ParseSiteUrl("sftp://example.com:99999999999/", s3Opts, fsErr));

    /* SessionStore: empty secret round-trip, corrupt base64 rejection, and
     * tab escaping in INI fields. */
    const std::string key32(32, 'K');
    std::string enc;
    std::string dec = "nonempty";
    CHECK_TRUE(SessionStore::EncryptPassword("", key32, enc, fsErr));
    CHECK_TRUE(enc.find("lscp1$") == 0);
    CHECK_TRUE(SessionStore::DecryptPassword(enc, key32, dec, fsErr));
    CHECK_EQ(dec, std::string(""));
    CHECK_FALSE(SessionStore::DecryptPassword("lscp1$!!!notbase64!!!", key32, dec, fsErr));

    const std::string storePath = tempDir + "/sessions.ini";
    {
        SessionStore store(storePath);
        StoredSession s;
        s.name = "tab\tsite";
        s.protocol = "sftp";
        s.hostName = "example.com";
        s.portNumber = 22;
        s.remoteDirectory = "/dir\twith\ttab";
        CHECK_FALSE(store.AddOrUpdate(s, fsErr));
        s.name = "tabsite";
        CHECK_TRUE(store.AddOrUpdate(s, fsErr));
        CHECK_TRUE(store.Save(fsErr));
    }
    {
        SessionStore reloaded(storePath);
        CHECK_TRUE(reloaded.Load(fsErr));
        const StoredSession * foundSite = reloaded.Find("tabsite");
        CHECK_TRUE(foundSite != NULL);
        if (foundSite != NULL)
        {
            CHECK_EQ(foundSite->remoteDirectory, std::string("/dir\twith\ttab"));
        }
    }

    /* PpkKey: reject excessive Argon2-Memory headers before allocation. */
    const std::string ppkPath = tempDir + "/huge.ppk";
    f = fopen(ppkPath.c_str(), "wb");
    if (f != NULL)
    {
        const char * badPpk =
            "PuTTY-User-Key-File-3: ssh-ed25519\n"
            "Encryption: aes256-cbc\n"
            "Comment: test\n"
            "Public-Lines: 1\n"
            "AAAAC3NzaC1lZDI1NTE5AAAAIA==\n"
            "Key-Derivation: Argon2id\n"
            "Argon2-Memory: 4194304\n"
            "Argon2-Passes: 1\n"
            "Argon2-Parallelism: 1\n"
            "Argon2-Salt: 0011223344556677\n"
            "Private-Lines: 1\n"
            "AAAA\n"
            "Private-MAC: 00\n";
        fwrite(badPpk, 1, strlen(badPpk), f);
        fclose(f);
    }
    std::string pemOut;
    CHECK_FALSE(PpkPrivateKeyPem(ppkPath, "pass", pemOut, fsErr));

    /* ScpParseHeaderLine: reject non-octal mode, size overflow, and control chars. */
    char kind = 0;
    unsigned int scpMode = 0;
    unsigned long long scpSize = 0;
    std::string scpName;
    unsigned long scpMtime = 0, scpAtime = 0;
    CHECK_FALSE(ScpParseHeaderLine("C0999 10 badmode", kind, scpMode, scpSize, scpName, scpMtime, scpAtime));
    CHECK_FALSE(ScpParseHeaderLine("C0644 99999999999999999999999999 huge", kind, scpMode, scpSize, scpName, scpMtime, scpAtime));
    CHECK_FALSE(ScpParseHeaderLine(std::string("C0644 10 bad\x01name"), kind, scpMode, scpSize, scpName, scpMtime, scpAtime));

    /* DavPropertyValueFromXml: skip 404 propstat and read 200 propstat. */
    std::string davVal;
    bool davFound = true;
    CHECK_FALSE(DavPropertyValueFromXml(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:lscp=\"urn:linscp:properties\">"
        "<d:response><d:propstat><d:prop><lscp:missing/></d:prop>"
        "<d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>"
        "</d:response></d:multistatus>",
        "missing", davVal, davFound));
    CHECK_FALSE(davFound);

    /* S3SigV4: UriEncode encodes UTF-8 and control bytes as uppercase %XX. */
    CHECK_EQ(s3sig::UriEncode("/a b/\xc3\xa9", true), std::string("/a%20b/%C3%A9"));

    /* SyncState: 0600 permissions and >8 KiB path round-trip. */
    const std::string statePath = tempDir + "/sync.state";
    const std::string longRel(9000, 'x');
    SyncState stateOut;
    SyncStateEntry rec;
    rec.localTime = 12345;
    rec.remoteTime = 12345;
    rec.size = 42;
    stateOut.Update(longRel, rec);
    CHECK_TRUE(stateOut.Save(statePath, fsErr));
    struct stat stBuf;
    CHECK_TRUE(stat(statePath.c_str(), &stBuf) == 0);
    CHECK_EQ(std::to_string(stBuf.st_mode & 0777), std::to_string(0600));
    SyncState stateIn;
    SyncStateEntry outRec;
    CHECK_TRUE(stateIn.Load(statePath, fsErr));
    CHECK_TRUE(stateIn.Lookup(longRel, outRec));
    CHECK_EQ(std::to_string(outRec.size), std::string("42"));

    /* Script option validation: 'option exclude *.bak' without '|',
     * 'option include a|b' rejected, 'option echo maybe' rejected, and
     * 'option editmaxsize' overflow rejected. */
    Script script;
    CHECK_TRUE(script.ExecuteLine("option exclude *.bak"));
    CHECK_FALSE(script.LastCommandFailed());
    script.ExecuteLine("option include *.txt|*.bak");
    CHECK_TRUE(script.LastCommandFailed());
    script.ExecuteLine("option echo maybe");
    CHECK_TRUE(script.LastCommandFailed());
    script.ExecuteLine("option editmaxsize 999999999999999999999999");
    CHECK_TRUE(script.LastCommandFailed());

    std::error_code ec;
    std::filesystem::remove_all(tempDir, ec);
}

int main()
{
    TestLocalization();
    TestSplitCommandLine();
    TestSplitCommands();
    TestRemotePaths();
    TestLocalPaths();
    TestMasks();
    TestMaskCase();
    TestPlatformServices();
    TestCurlProgress();
    TestFormatting();
    TestDateParsing();
    TestTerminalCommandLine();
    TestDesktopSessionDetection();
    TestParseSiteUrl();
    TestLocalFs();
    TestSessionRegistry();
    TestScriptCommands();
    TestFileMaskParsing();
    TestSyncPlannerModes();
    TestSyncPlannerCriteria();
    TestSyncCriteriaParsing();
    TestSyncPlannerMaskAndRecursion();
    TestSyncPlannerConflictsAndState();
    TestSyncPlanOrder();
    TestSyncStateFile();
    TestProxySettings();
    TestFtpPassiveReplyParsing();
    TestFtpAndTlsSettings();
    TestHostKeyPinConversion();
    TestDavLockAndPropertyXml();
    TestSessionStore();
    TestS3SigV4();
    TestEditorHelpers();
    TestRemoteEditor();
    TestS3ObjectSettings();
    TestNewScriptCommands();
    TestPermissionModes();
    TestServerReplyHardening();
    TestNameAbbreviations();
    TestScriptParameterExpansion();
    TestTimestampFormatting();
    TestRelativeTime();
    TestNonUnixListingFormats();
    TestEncodingHelpers();
    TestSshTunnelParsing();
    TestCurlTunnelArgs();
    TestSocks5Helpers();
    TestSshJumpSettings();
    TestDavEtagHelpers();
    TestScpEngine();
    TestScpHeaderNamesCannotTraverse();
    TestAuditRegressions();

    if (gFailures != 0)
    {
        printf("%d of %d checks failed\n", gFailures, gChecks);
        return 1;
    }
    printf("All %d checks passed\n", gChecks);
    return 0;
}
