#include "Console.h"

#include "Platform.h"
#include "Texts.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace linscp {

Console & Console::Instance()
{
    static Console console;
    return console;
}

namespace {

/*
 * Text of the log, with the characters that would end an element early
 * replaced by their entity. Control characters other than a tab cannot
 * appear in XML at all, so they are dropped: a server may put them in a file
 * name and the log must stay readable by an XML parser.
 */
std::string EscapeXml(const std::string & text)
{
    std::string result;
    for (size_t i = 0; i < text.size(); i++)
    {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        switch (c)
        {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            case '\t': result += "\t"; break;
            case '\r': result += "&#13;"; break;
            default:
                if (c >= 0x20 || c == 0x0a)
                {
                    result += static_cast<char>(c);
                }
                break;
        }
    }
    return result;
}

std::string Timestamp()
{
    char buffer[64];
    const std::time_t now = std::time(NULL);
    struct tm tmResult;
    if (!LocalTime(now, tmResult))
    {
        return "unknown";
    }
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tmResult);
    return buffer;
}

} // namespace

Console::Console() :
    mBatchMode(false),
    mVerbose(false),
    mLog(NULL),
    mActionLog(NULL),
    mTransferSize(0),
    mLastPermille(0)
{
}

Console::~Console()
{
    CloseLogFile();
    CloseActionLogFile();
}

bool Console::IsInteractive() const
{
    return !mBatchMode && StdInIsTerminal();
}

void Console::Write(const std::string & text)
{
    fputs(text.c_str(), stdout);
    fflush(stdout);
}

void Console::WriteLine(const std::string & text)
{
    fputs(text.c_str(), stdout);
    fputc('\n', stdout);
    fflush(stdout);
    if (mActionLog != NULL)
    {
        LogAction("message", "type=\"output\"", text);
    }
}

void Console::Status(const std::string & text)
{
    WriteLine(text);
}

void Console::Error(const std::string & text)
{
    fputs(text.c_str(), stderr);
    fputc('\n', stderr);
    fflush(stderr);
    if (mActionLog != NULL)
    {
        LogAction("message", "type=\"error\"", text);
    }
}

void Console::Fatal(const std::string & text)
{
    Error(text);
}

void Console::LogEvent(const std::string & text)
{
    if (mVerbose)
    {
        WriteLine(text);
    }
    if (mLog != NULL)
    {
        char stamp[64];
        time_t now = time(NULL);
        struct tm tmResult;
        if (LocalTime(now, tmResult))
        {
            strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmResult);
            fprintf(mLog, ". %s Event: %s\n", stamp, text.c_str());
            fflush(mLog);
        }
    }
}

bool Console::ReadLine(const std::string & prompt, std::string & line)
{
    if (!prompt.empty())
    {
        Write(prompt);
    }
    line.clear();
    int c;
    bool any = false;
    while ((c = fgetc(stdin)) != EOF)
    {
        any = true;
        if (c == '\n')
        {
            return true;
        }
        if (c != '\r')
        {
            line += static_cast<char>(c);
        }
    }
    if (any && !line.empty())
    {
        return true;
    }
    return false;
}

bool Console::ReadPassword(const std::string & prompt, std::string & password)
{
    password.clear();
    Write(prompt);
    bool result = false;
    bool echoWasOff = false;
    {
        EchoOff echoOff;
        echoWasOff = echoOff.Active();
        int c;
        while ((c = fgetc(stdin)) != EOF)
        {
            if (c == '\n')
            {
                result = true;
                break;
            }
            if (c != '\r')
            {
                password += static_cast<char>(c);
            }
        }
    } /* EchoOff restores the console mode here. */
    if (echoWasOff)
    {
        /* Print the newline that the user's Enter would have echoed. */
        fputc('\n', stdout);
        fflush(stdout);
    }
    return result;
}

bool Console::Confirm(const std::string & prompt, bool defaultYes)
{
    /* Never consume stdin from a script or silently approve a destructive
     * action when there is no terminal to answer the prompt. */
    if (!IsInteractive())
    {
        return false;
    }
    std::string answer;
    std::string full = prompt + Texts::Translate(defaultYes ? " [Y/n]: " : " [y/N]: ");
    if (!ReadLine(full, answer))
    {
        return false;
    }
    if (answer.empty())
    {
        return defaultYes;
    }
    return (answer[0] == 'y' || answer[0] == 'Y' ||
        ((answer[0] == 's' || answer[0] == 'S') &&
         Texts::Translate("yes") == "sí"));
}

bool Console::SetLogFile(const std::string & path, std::string & error)
{
    CloseLogFile();
    /* Binary append: the log also records raw traffic (LogTraffic),
     * which a text-mode stream would corrupt. */
    mLog = fopen(path.c_str(), "ab");
    if (mLog == NULL)
    {
        error = std::string(strerror(errno));
        return false;
    }
    char stamp[64];
    time_t now = time(NULL);
    struct tm tmResult;
    if (LocalTime(now, tmResult))
    {
        strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmResult);
        fprintf(mLog, "= session opened %s =\n", stamp);
        fflush(mLog);
    }
    return true;
}

void Console::LogTraffic(const void * data, size_t len, bool incoming)
{
    if (mLog == NULL || len == 0)
    {
        return;
    }
    fputc(incoming ? '<' : '>', mLog);
    fputc(' ', mLog);
    fwrite(data, 1, len, mLog);
    fflush(mLog);
}

bool Console::SetActionLogFile(const std::string & path, std::string & error)
{
    CloseActionLogFile();
    mActionLog = fopen(path.c_str(), "wb");
    if (mActionLog == NULL)
    {
        error = std::strerror(errno);
        return false;
    }
    fprintf(mActionLog, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(mActionLog, "<log_session client=\"%s\" created=\"%s\">\n",
        EscapeXml(linscp::Texts::VersionLine()).c_str(), Timestamp().c_str());
    fflush(mActionLog);
    return true;
}

std::string Console::EscapeActionText(const std::string & text)
{
    return EscapeXml(text);
}

void Console::LogAction(const std::string & element,
    const std::string & attributes, const std::string & text)
{
    if (mActionLog == NULL)
    {
        return;
    }
    fprintf(mActionLog, "  <%s time=\"%s\"%s", element.c_str(),
        Timestamp().c_str(), attributes.empty() ? "" : (" " + attributes).c_str());
    if (text.empty())
    {
        fputs("/>\n", mActionLog);
    }
    else
    {
        fputs(">", mActionLog);
        fputs(EscapeXml(text).c_str(), mActionLog);
        fprintf(mActionLog, "</%s>\n", element.c_str());
    }
    fflush(mActionLog);
}

void Console::CloseActionLogFile()
{
    if (mActionLog != NULL)
    {
        fprintf(mActionLog, "</log_session>\n");
        fclose(mActionLog);
        mActionLog = NULL;
    }
}

void Console::CloseLogFile()
{
    if (mLog != NULL)
    {
        fputs("= session closed =\n", mLog);
        fclose(mLog);
        mLog = NULL;
    }
}

void Console::TransferStart(const std::string & fileName, uint64_t totalSize)
{
    mTransferSize = totalSize;
    mTransferName = fileName;
    mLastPermille = 0;
    if (mBatchMode || !StdOutIsTerminal())
    {
        return;
    }
    Write(fileName);
    if (totalSize > 0)
    {
        size_t pad = fileName.size() < 24 ? 24 - fileName.size() : 1;
        for (size_t i = 0; i < pad; i++)
        {
            fputc(' ', stdout);
        }
        fputs("|          0.0%", stdout);
    }
    fflush(stdout);
}

void Console::TransferProgress(uint64_t transferred)
{
    if (mBatchMode || !StdOutIsTerminal() || mTransferSize == 0)
    {
        return;
    }
    unsigned long long permille =
        static_cast<unsigned long long>((transferred * 1000) / mTransferSize);
    if (permille > 1000)
    {
        permille = 1000;
    }
    if (permille == mLastPermille)
    {
        return;
    }
    mLastPermille = permille;
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "\r|  %3llu.%llu%%    ",
        permille / 10, permille % 10);
    fputs(buffer, stdout);
    fflush(stdout);
}

void Console::TransferEnd(bool success)
{
    if (mActionLog != NULL)
    {
        LogAction("transfer", "file=\"" + EscapeXml(mTransferName) + "\" status=\"" +
            std::string(success ? "ok" : "failed") + "\"", std::string());
    }
    mTransferName.clear();
    if (mBatchMode || !StdOutIsTerminal() || mTransferSize == 0)
    {
        return;
    }
    fputs(success ? "\r|  100.0%    \n" : "\n", stdout);
    fflush(stdout);
    mTransferSize = 0;
}

} // namespace linscp
