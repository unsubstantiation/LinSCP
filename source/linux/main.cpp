/*
 * main: command line entry point of the front end.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <cerrno>
#include <string>
#include <vector>

#include "Console.h"
#include "PathUtil.h"
#include "Platform.h"
#include "PpkKey.h"
#include "Script.h"
#include "Session.h"
#include "Texts.h"

#include <csignal>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>


namespace {

bool StartsWith(const char * text, const char * prefix, const char ** value)
{
    size_t len = strlen(prefix);
    if (strncmp(text, prefix, len) != 0)
    {
        return false;
    }
    if (value != NULL)
    {
        *value = text + len;
    }
    return true;
}

bool ParsePositiveInteger(const char * text, int maximum, int * result)
{
    if (text == NULL || text[0] == '\0')
    {
        return false;
    }
    unsigned int value = 0;
    for (const unsigned char * p =
             reinterpret_cast<const unsigned char *>(text); *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
        {
            return false;
        }
        const unsigned int digit = *p - '0';
        if (value > (static_cast<unsigned int>(maximum) - digit) / 10U)
        {
            return false;
        }
        value = value * 10U + digit;
    }
    if (value == 0 || value > static_cast<unsigned int>(maximum))
    {
        return false;
    }
    *result = static_cast<int>(value);
    return true;
}

/* The remote shell's output goes to stdout exactly as it arrived: this
 * mode is a byte pipe with a PTY on the far end, which is what the
 * graphical client's embedded terminal spawns. */
void ShellOutputSink(void * ctx, const char * data, size_t len)
{
    (void)ctx;
    fwrite(data, 1, len, stdout);
    fflush(stdout);
}

volatile sig_atomic_t g_windowChanged = 0;

void OnWindowChanged(int)
{
    g_windowChanged = 1;
}

int TerminalColumns()
{
    struct winsize size;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0)
    {
        return size.ws_col;
    }
    return 80;
}

int TerminalRows()
{
    struct winsize size;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_row > 0)
    {
        return size.ws_row;
    }
    return 24;
}

/*
 * 'linscp -shell sftp://user@host/': an interactive shell on the server
 * with stdin/stdout as a raw byte pipe. The graphical client runs this
 * behind a pseudo-terminal and renders it with xterm.js; run from a
 * real terminal it behaves like ssh without the file commands. The
 * exit status is the shell's.
 */
int RunShell(linscp::SessionOptions options, const std::string & url,
    linscp::Console & console)
{
    std::string error;
    if (!linscp::ParseSiteUrl(url, options, error))
    {
        console.Error(error);
        return 1;
    }
    if (!linscp::UseNativeSftp(options.protocol) &&
        !linscp::UseNativeScp(options.protocol))
    {
        console.Error(linscp::Texts::Translate(
            "A shell is only available for SSH (sftp:// or scp://) "
            "sessions, not for '{protocol}'.",
            {{"protocol", options.protocol}}));
        return 1;
    }
    options.protocol = "sftp";

    linscp::Session session;
    session.SetOutputSink(ShellOutputSink, NULL);
    if (!session.OpenShell(options, TerminalColumns(), TerminalRows(), error))
    {
        console.Error(error);
        return 1;
    }

    /* Raw mode on a real terminal: the server side echoes and edits. */
    struct termios original;
    const bool rawMode = tcgetattr(STDIN_FILENO, &original) == 0;
    if (rawMode)
    {
        struct termios raw = original;
        cfmakeraw(&raw);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = OnWindowChanged;
        sigaction(SIGWINCH, &action, NULL);
    }

    bool inputOpen = true;
    while (session.IsAlive())
    {
        if (g_windowChanged)
        {
            g_windowChanged = 0;
            session.ShellResize(TerminalColumns(), TerminalRows());
        }
        struct pollfd fds[1];
        fds[0].fd = STDIN_FILENO;
        fds[0].events = POLLIN;
        const int ready = poll(fds, inputOpen ? 1 : 0, 20);
        if (ready > 0 && (fds[0].revents & (POLLIN | POLLHUP | POLLERR)))
        {
            char buffer[4096];
            const ssize_t got = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (got <= 0)
            {
                inputOpen = false;
                session.SendEof();
            }
            else if (!session.SendData(buffer, static_cast<size_t>(got)))
            {
                break;
            }
        }
        session.Pump();
    }
    const int exitCode = session.ExitCode();
    session.Close();
    if (rawMode)
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &original);
    }
    if (!session.ConnectionError().empty())
    {
        console.Error(session.ConnectionError());
        return 1;
    }
    return exitCode == INT_MAX ? 1 : exitCode;
}

} // namespace

int main(int argc, char ** argv)
{
    linscp::InitConsole();
    linscp::Console & console = linscp::Console::Instance();
    linscp::SessionOptions options;
    std::string scriptFile;
    std::string command;
    std::string url;
    std::string logFile;
    std::string xmlLogFile;
    std::string convertKeyInput;
    std::string convertKeyOutput;
    /* The script parameters of this run, substituted for %1% .. %9%. */
    std::vector<std::string> parameters;
    bool collectingParameters = false;
    bool batch = false;
    bool launchGui = false;
    bool serverMode = false;
    bool shellMode = false;
    bool help = false;
    bool version = false;
    bool scriptSpecified = false;
    bool commandSpecified = false;
    bool literalCommand = false;
    bool convertKeySpecified = false;
    bool convertOutputSpecified = false;
    const char * value = NULL;

    for (int i = 1; i < argc; i++)
    {
        const char * arg = argv[i];
        if (collectingParameters)
        {
            /* WinSCP takes the script parameters after a bare '/parameter';
             * they are not the site URL, however they look. */
            parameters.push_back(arg);
            continue;
        }
        if (strcmp(arg, "-parameter") == 0 || strcmp(arg, "--parameter") == 0 ||
            strcmp(arg, "-parameters") == 0)
        {
            collectingParameters = true;
        }
        else if (StartsWith(arg, "-parameter=", &value))
        {
            parameters.push_back(value);
        }
        else if (StartsWith(arg, "-script=", &value))
        {
            scriptSpecified = true;
            scriptFile = linscp::ExpandTilde(value);
        }
        else if (StartsWith(arg, "-command=", &value))
        {
            commandSpecified = true;
            command = value;
        }
        else if (strcmp(arg, "-literal") == 0)
        {
            /* A GUI command contains literal file names, not script
             * parameters or environment/timestamp placeholders. */
            literalCommand = true;
        }
        else if (strcmp(arg, "-rawsettings") == 0 || StartsWith(arg, "-rawsettings=", &value))
        {
            int count = -1;
            if (strcmp(arg, "-rawsettings") != 0 &&
                !ParsePositiveInteger(value, argc, &count))
            {
                console.Error(linscp::Texts::Translate(
                    "-rawsettings requires a positive setting count."));
                return 1;
            }
            int taken = 0;
            while (i + 1 < argc && (count < 0 || taken < count))
            {
                const std::string setting = argv[i + 1];
                const size_t equals = setting.find('=');
                if (setting.empty() || setting[0] == '-' || equals == std::string::npos)
                    break;
                std::string error;
                if (!linscp::ApplySessionRawSetting(setting.substr(0, equals),
                        setting.substr(equals + 1), options, error))
                {
                    console.Error(error);
                    return 1;
                }
                ++i;
                ++taken;
            }
            if (taken == 0 || (count >= 0 && taken != count))
            {
                console.Error(linscp::Texts::Translate(
                    "-rawsettings requires NAME=VALUE arguments matching its count."));
                return 1;
            }
        }
        else if (StartsWith(arg, "-hostkey=", &value))
        {
            options.hostKey = value;
        }
        else if (StartsWith(arg, "-password=", &value))
        {
            options.password = value;
        }
        else if (StartsWith(arg, "-privatekey=", &value))
        {
            options.privateKeyFile = value;
        }
        else if (StartsWith(arg, "-passphrase=", &value))
        {
            options.keyPassphrase = value;
        }
        else if (StartsWith(arg, "-convertkey=", &value))
        {
            convertKeySpecified = true;
            convertKeyInput = value;
        }
        else if (StartsWith(arg, "-output=", &value))
        {
            convertOutputSpecified = true;
            convertKeyOutput = value;
        }
        else if (StartsWith(arg, "-username=", &value))
        {
            options.userName = value;
        }
        else if (StartsWith(arg, "-port=", &value))
        {
            if (!ParsePositiveInteger(value, 65535, &options.portNumber))
            {
                console.Error(linscp::Texts::Translate("Invalid port number '{value}' (expected 1 through 65535).", {{"value", value}}));
                return 1;
            }
        }
        else if (StartsWith(arg, "-timeout=", &value))
        {
            if (!ParsePositiveInteger(value, INT_MAX / 1000, &options.timeoutSecs))
            {
                console.Error(linscp::Texts::Translate("Invalid timeout '{value}' (expected a positive number of seconds).", {{"value", value}}));
                return 1;
            }
        }
        else if (StartsWith(arg, "-log=", &value))
        {
            logFile = linscp::ExpandTilde(value);
        }
        else if (StartsWith(arg, "-xmllog=", &value))
        {
            xmlLogFile = linscp::ExpandTilde(value);
        }
        else if (strcmp(arg, "-batch") == 0 || strcmp(arg, "-batch=on") == 0)
        {
            batch = true;
        }
        else if (strcmp(arg, "-batch=off") == 0)
        {
            batch = false;
        }
        else if (strcmp(arg, "-gui") == 0 || strcmp(arg, "--gui") == 0)
        {
            launchGui = true;
        }
        else if (strcmp(arg, "-server") == 0 || strcmp(arg, "--server") == 0)
        {
            serverMode = true;
        }
        else if (strcmp(arg, "-shell") == 0 || strcmp(arg, "--shell") == 0)
        {
            shellMode = true;
        }
        else if (strcmp(arg, "-verbose") == 0)
        {
            options.verbose = true;
        }
        else if (strcmp(arg, "-version") == 0 || strcmp(arg, "--version") == 0)
        {
            version = true;
        }
        else if (strcmp(arg, "-help") == 0 || strcmp(arg, "--help") == 0 ||
            strcmp(arg, "-h") == 0)
        {
            help = true;
        }
        else if (arg[0] == '-' && arg[1] != '\0')
        {
            console.Error(linscp::Texts::Translate("Unknown option '{argument}'.", {{"argument", arg}}));
            console.Error(linscp::Texts::Usage());
            return 1;
        }
        else if (url.empty())
        {
            url = arg;
        }
        else
        {
            console.Error(linscp::Texts::Translate("Unexpected argument '{argument}'.", {{"argument", arg}}));
            return 1;
        }
    }

    if (launchGui && (convertKeySpecified || convertOutputSpecified))
    {
        console.Error(linscp::Texts::Translate(
            "Key conversion syntax: linscp -convertkey=INPUT.ppk -output=OUTPUT.pem [-passphrase=PASSPHRASE]."));
        return 1;
    }
    if (launchGui)
    {
        std::string guiError;
        if (!linscp::LaunchGuiApplication(guiError))
        {
            console.Error(guiError);
            return 1;
        }
        return 0;
    }

    if (version)
    {
        console.WriteLine(linscp::Texts::VersionLine());
        return 0;
    }
    if (help)
    {
        console.WriteLine(linscp::Texts::Usage());
        return 0;
    }
    if (convertKeySpecified)
    {
        if (convertKeyInput.empty() || convertKeyOutput.empty() || !url.empty() || scriptSpecified ||
            commandSpecified || serverMode || shellMode || launchGui)
        {
            console.Error(linscp::Texts::Translate(
                "Key conversion syntax: linscp -convertkey=INPUT.ppk -output=OUTPUT.pem [-passphrase=PASSPHRASE]."));
            return 1;
        }
        std::string error;
        const std::string input = linscp::ExpandTilde(convertKeyInput);
        const std::string output = linscp::ExpandTilde(convertKeyOutput);
        std::string passphrase = options.keyPassphrase;
        for (int attempt = 0; attempt < 3; ++attempt)
        {
            if (linscp::ConvertPpkToOpenSsh(input, output, passphrase, error))
            {
                console.WriteLine(linscp::Texts::Translate(
                    "Converted key written to '{path}'.", {{"path", output}}));
                return 0;
            }
            if (error.find("integrity check failed") == std::string::npos ||
                !passphrase.empty() || batch || !console.IsInteractive() || attempt == 2)
                break;
            if (!console.ReadPassword("PPK key passphrase: ", passphrase))
                break;
        }
        console.Error(error);
        return 1;
    }
    if (convertOutputSpecified)
    {
        console.Error(linscp::Texts::Translate(
            "-output is only valid with -convertkey."));
        return 1;
    }
    if (serverMode && (scriptSpecified || commandSpecified))
    {
        console.Error(linscp::Texts::Translate("-server reads commands from standard input and cannot be combined with -script or -command."));
        return 1;
    }
    if (shellMode && (scriptSpecified || commandSpecified || serverMode))
    {
        console.Error(linscp::Texts::Translate("-shell opens an interactive shell on the site given as the argument and cannot be combined with -script, -command or -server."));
        return 1;
    }
    if (shellMode && url.empty())
    {
        console.Error(linscp::Texts::Translate("-shell requires a site URL, for example sftp://user@example.com/."));
        return 1;
    }
    if (scriptSpecified && commandSpecified)
    {
        console.Error(linscp::Texts::Translate("Choose either -script or -command, not both."));
        return 1;
    }
    if (literalCommand && !commandSpecified)
    {
        console.Error(linscp::Texts::Translate("-literal requires -command; scripts and interactive commands still expand parameters."));
        return 1;
    }
    if (scriptSpecified && scriptFile.empty())
    {
        console.Error(linscp::Texts::Translate("-script requires a file name (use -script=- for standard input)."));
        return 1;
    }
    if (commandSpecified && command.empty())
    {
        console.Error(linscp::Texts::Translate("-command requires at least one command."));
        return 1;
    }
    if ((scriptSpecified || commandSpecified) && !url.empty())
    {
        console.Error(linscp::Texts::Translate("A site URL cannot be combined with -script or -command; put an 'open' command in the script instead."));
        return 1;
    }

    if (options.password.empty())
    {
        const char * password = getenv("LINSCP_PASSWORD");
        if (password != NULL)
        {
            options.password = password;
        }
    }

    // The GUI keeps tab-only pins in memory and persists each hop only when
    // its own Remember checkbox is selected. CLI pin caching stays unchanged.
    const char * cachePins = getenv("LINSCP_CACHE_PINNED_HOSTKEYS");
    options.cachePinnedHostKeys = cachePins == NULL || std::strcmp(cachePins, "0") != 0;

    // Like LINSCP_PASSWORD, these belong to this core process, never a
    // subprocess command line. The GUI clears inherited values per session.
    if (options.tunnel.password.empty())
    {
        const char * secret = getenv("LINSCP_TUNNEL_PASSWORD");
        if (secret != NULL) options.tunnel.password = secret;
    }
    if (options.tunnel.keyPassphrase.empty())
    {
        const char * secret = getenv("LINSCP_TUNNEL_PASSPHRASE");
        if (secret != NULL) options.tunnel.keyPassphrase = secret;
    }

    if (!logFile.empty())
    {
        std::string error;
        if (!console.SetLogFile(logFile, error))
        {
            console.Error(linscp::Texts::Translate("Cannot open the log file '{path}': {reason}", {{"path", logFile}, {"reason", error}}));
            return 1;
        }
    }
    if (!xmlLogFile.empty())
    {
        std::string error;
        if (!console.SetActionLogFile(xmlLogFile, error))
        {
            console.Error(linscp::Texts::Translate("Cannot open the XML log file '{path}': {reason}", {{"path", xmlLogFile}, {"reason", error}}));
            return 1;
        }
    }

    console.SetBatchMode(batch);
    console.SetVerbose(options.verbose);

    linscp::Script script;
    script.SetDefaults(options);
    script.SetScriptParameters(parameters);

    int result;
    if (shellMode)
    {
        result = RunShell(options, url, console);
    }
    else if (serverMode)
    {
        result = script.RunServer();
    }
    else if (scriptSpecified)
    {
        result = script.RunFile(scriptFile);
    }
    else if (commandSpecified)
    {
        result = script.RunCommand(command, literalCommand);
    }
    else if (!console.IsInteractive() && url.empty())
    {
        console.Error(linscp::Texts::Translate("No input. Pass -script, -command or a site URL, or run interactively from a terminal."));
        console.Error(linscp::Texts::Usage());
        result = 1;
    }
    else
    {
        result = script.RunInteractive(url);
    }

    return result;
}
