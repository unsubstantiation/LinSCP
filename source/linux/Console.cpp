#include "Console.h"

#include "Platform.h"
#include "Texts.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sys/stat.h>
#include <sys/time.h>

namespace linscp {

Console & Console::Instance()
{
    static Console console;
    return console;
}

/*
 * XML log escaping, in upstream's two spellings. An attribute value has
 * its newline written as a character reference, because an XML reader
 * folds a literal one to a space and a '<call>' output would lose its
 * lines; element text keeps the newline. A carriage return is dropped
 * by both (upstream deletes it), and so are the control characters XML
 * cannot represent at all: a server may put them in a file name and the
 * log must stay readable by an XML parser.
 */
static std::string EscapeXml(const std::string & text, bool attribute)
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
            case '"':
                result += attribute ? "&quot;" : "\"";
                break;
            case '\r':
                break;
            case '\n':
                result += attribute ? "&#10;" : "\n";
                break;
            case '\t':
                result += "\t";
                break;
            default:
                if (c >= 0x20)
                {
                    result += static_cast<char>(c);
                }
                break;
        }
    }
    return result;
}

std::string Console::EscapeXmlAttr(const std::string & text)
{
    return EscapeXml(text, true);
}

std::string Console::EscapeXmlText(const std::string & text)
{
    return EscapeXml(text, false);
}

std::string Console::XmlTimestamp(unsigned long epochSeconds)
{
    char buffer[48];
    const std::time_t when = static_cast<std::time_t>(epochSeconds);
    struct tm tmResult;
    if (gmtime_r(&when, &tmResult) == NULL)
    {
        return "1970-01-01T00:00:00.000Z";
    }
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S.000Z", &tmResult);
    return buffer;
}

std::string Console::XmlTimestampNow()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    std::string stamp = XmlTimestamp(static_cast<unsigned long>(now.tv_sec));
    char millis[8];
    snprintf(millis, sizeof(millis), ".%03dZ",
        static_cast<int>(now.tv_usec / 1000));
    stamp.replace(stamp.size() - 5, 5, millis);
    return stamp;
}

Console::Console() :
    mBatchMode(false),
    mVerbose(false),
    mQuiet(false),
    mLog(NULL),
    mActionLog(NULL),
    mXmlHeaderWritten(false),
    mXmlInGroup(false),
    mXmlSessionName("nosession"),
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
    /* Console output is not part of the XML log format: upstream records
     * operations and failures there, never the text it printed. */
}

void Console::Status(const std::string & text)
{
    if (!mQuiet)
    {
        WriteLine(text);
    }
}

void Console::Error(const std::string & text)
{
    fputs(text.c_str(), stderr);
    fputc('\n', stderr);
    fflush(stderr);
    if (mActionLog != NULL)
    {
        /* Kept for the '<failure>' of the command that is running; the
         * script engine collects and masks them when the group closes. */
        mXmlErrors.push_back(text);
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

bool Console::SetLogFile(const std::string & path, std::string & error,
    unsigned long long maxBytes, int maxCount)
{
    CloseLogFile();
    /*
     * Upstream's '/logsize=' rotation: when the file has reached its
     * limit, the old files move one slot down and the current one
     * becomes '<path>.1'. A rotation that cannot rename a file is left
     * alone - the log opening below then reports the real problem - so
     * that a read-only directory is not reported as a wrong size.
     */
    if (maxBytes > 0 && maxCount > 0)
    {
        struct stat info;
        if (stat(path.c_str(), &info) == 0 &&
            info.st_size >= static_cast<off_t>(maxBytes))
        {
            char name[4096];
            snprintf(name, sizeof(name), "%s.%d", path.c_str(), maxCount);
            remove(name);
            for (int index = maxCount - 1; index >= 1; index--)
            {
                char from[4096];
                char to[4096];
                snprintf(from, sizeof(from), "%s.%d", path.c_str(), index);
                snprintf(to, sizeof(to), "%s.%d", path.c_str(), index + 1);
                if (rename(from, to) != 0 && errno != ENOENT)
                {
                    break;
                }
            }
            char first[4096];
            snprintf(first, sizeof(first), "%s.1", path.c_str());
            rename(path.c_str(), first);
        }
    }
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
    /* Nothing is written yet: the '<session>' header carries the name of
     * the connection, which is only known when 'open' succeeds, so it is
     * written by XmlEnsureHeader() at the first group that needs it. */
    mXmlHeaderWritten = false;
    mXmlInGroup = false;
    mXmlPendingGroup.clear();
    mXmlSessionName = "nosession";
    mXmlErrors.clear();
    return true;
}

void Console::XmlSessionName(const std::string & name)
{
    if (!name.empty() && !mXmlHeaderWritten)
    {
        mXmlSessionName = name;
    }
    /* A held-back '<group>' can go out now under the right name. */
    if (!mXmlPendingGroup.empty())
    {
        XmlEnsureHeader();
    }
}

void Console::XmlEnsureHeader()
{
    if (mActionLog == NULL || mXmlHeaderWritten)
    {
        return;
    }
    fprintf(mActionLog, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(mActionLog,
        "<session xmlns=\"http://winscp.net/schema/session/1.0\" "
        "name=\"%s\" start=\"%s\">\n",
        EscapeXmlAttr(mXmlSessionName).c_str(), XmlTimestampNow().c_str());
    fflush(mActionLog);
    mXmlHeaderWritten = true;
    if (!mXmlPendingGroup.empty())
    {
        XmlWriteLine(1, mXmlPendingGroup);
        fflush(mActionLog);
        mXmlPendingGroup.clear();
    }
}

void Console::XmlWriteLine(int depth, const std::string & text)
{
    fprintf(mActionLog, "%*s%s\n", depth * 2, "", text.c_str());
}

void Console::XmlBeginGroup(const std::string & name)
{
    if (mActionLog == NULL)
    {
        return;
    }
    if (mXmlInGroup)
    {
        /* Groups do not nest; a command that starts another (an editor
         * round trip inside 'edit') belongs to the group already open. */
        return;
    }
    mXmlErrors.clear();
    const std::string line = "<group name=\"" + EscapeXmlAttr(name) +
        "\" start=\"" + XmlTimestampNow() + "\">";
    mXmlInGroup = true;
    if (mXmlHeaderWritten)
    {
        XmlWriteLine(1, line);
        fflush(mActionLog);
    }
    else
    {
        /* Hold this first group back: if it is the 'open' that creates
         * the session, XmlSessionName() is about to name the header.
         * Anything else that writes (an action, the failure, the end of
         * the group, closing the file) flushes it as 'nosession'. */
        mXmlPendingGroup = line;
    }
}

void Console::XmlEndGroup()
{
    if (mActionLog == NULL || !mXmlInGroup)
    {
        return;
    }
    XmlEnsureHeader();
    XmlWriteLine(1, "</group>");
    fflush(mActionLog);
    mXmlInGroup = false;
    mXmlErrors.clear();
}

std::vector<std::string> Console::TakeActionErrors()
{
    std::vector<std::string> errors;
    errors.swap(mXmlErrors);
    return errors;
}

void Console::XmlFailure(const std::vector<std::string> & messages)
{
    if (mActionLog == NULL || messages.empty())
    {
        return;
    }
    XmlEnsureHeader();
    const int depth = mXmlInGroup ? 2 : 1;
    XmlWriteLine(depth, "<failure>");
    for (size_t i = 0; i < messages.size(); i++)
    {
        XmlWriteLine(depth + 1, "<message>" + EscapeXmlText(messages[i]) +
            "</message>");
    }
    XmlWriteLine(depth, "</failure>");
    fflush(mActionLog);
}

void Console::XmlWriteParams(int depth, const XmlParams & params)
{
    for (size_t i = 0; i < params.size(); i++)
    {
        if (params[i].second.empty())
        {
            XmlWriteLine(depth, "<" + params[i].first + " />");
        }
        else
        {
            XmlWriteLine(depth, "<" + params[i].first + " value=\"" +
                EscapeXmlAttr(params[i].second) + "\" />");
        }
    }
}

void Console::XmlWriteResult(int depth, bool success, const std::string & error)
{
    if (success)
    {
        XmlWriteLine(depth, "<result success=\"true\" />");
    }
    else if (error.empty())
    {
        XmlWriteLine(depth, "<result success=\"false\" />");
    }
    else
    {
        XmlWriteLine(depth, "<result success=\"false\">");
        XmlWriteLine(depth + 1, "<message>" + EscapeXmlText(error) +
            "</message>");
        XmlWriteLine(depth, "</result>");
    }
}

void Console::XmlWriteFile(int depth, const XmlFileInfo & file, bool withName)
{
    XmlWriteLine(depth, "<file>");
    XmlParams params;
    if (withName)
    {
        params.push_back(std::make_pair("filename", file.name));
    }
    params.push_back(std::make_pair("type", std::string(1, file.type)));
    if (file.hasSize)
    {
        params.push_back(std::make_pair("size",
            std::to_string(file.size)));
    }
    if (file.hasModification)
    {
        params.push_back(std::make_pair("modification",
            XmlTimestamp(file.modification)));
    }
    if (!file.permissions.empty())
    {
        params.push_back(std::make_pair("permissions", file.permissions));
    }
    if (!file.owner.empty())
    {
        params.push_back(std::make_pair("owner", file.owner));
    }
    if (!file.group.empty())
    {
        params.push_back(std::make_pair("group", file.group));
    }
    XmlWriteParams(depth + 1, params);
    XmlWriteLine(depth, "</file>");
}

void Console::XmlAction(const std::string & element, const XmlParams & params,
    bool success, const std::string & error, bool recursive)
{
    if (mActionLog == NULL)
    {
        return;
    }
    XmlEnsureHeader();
    const int depth = mXmlInGroup ? 2 : 1;
    XmlWriteLine(depth, "<" + element +
        (recursive ? " recursive=\"true\"" : "") + ">");
    XmlWriteParams(depth + 1, params);
    XmlWriteResult(depth + 1, success, error);
    XmlWriteLine(depth, "</" + element + ">");
    fflush(mActionLog);
}

void Console::XmlActionFiles(const std::string & element,
    const XmlParams & params, const std::vector<XmlFileInfo> & files,
    bool success, const std::string & error)
{
    if (mActionLog == NULL)
    {
        return;
    }
    XmlEnsureHeader();
    const int depth = mXmlInGroup ? 2 : 1;
    XmlWriteLine(depth, "<" + element + ">");
    XmlWriteParams(depth + 1, params);
    XmlWriteLine(depth + 1, "<files>");
    for (size_t i = 0; i < files.size(); i++)
    {
        XmlWriteFile(depth + 2, files[i], true);
    }
    XmlWriteLine(depth + 1, "</files>");
    XmlWriteResult(depth + 1, success, error);
    XmlWriteLine(depth, "</" + element + ">");
    fflush(mActionLog);
}

void Console::XmlActionFile(const std::string & element,
    const XmlParams & params, const XmlFileInfo & file, bool success,
    const std::string & error)
{
    if (mActionLog == NULL)
    {
        return;
    }
    XmlEnsureHeader();
    const int depth = mXmlInGroup ? 2 : 1;
    XmlWriteLine(depth, "<" + element + ">");
    XmlWriteParams(depth + 1, params);
    if (success)
    {
        XmlWriteFile(depth + 1, file, false);
    }
    XmlWriteResult(depth + 1, success, error);
    XmlWriteLine(depth, "</" + element + ">");
    fflush(mActionLog);
}

void Console::CloseActionLogFile()
{
    if (mActionLog != NULL)
    {
        /* A log of a run that never got as far as a command is still one
         * complete document, not a half element. */
        XmlEnsureHeader();
        XmlEndGroup();
        fprintf(mActionLog, "</session>\n");
        fclose(mActionLog);
        mActionLog = NULL;
        mXmlHeaderWritten = false;
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
    /* The transfer itself is an '<upload>'/'<download>' element the
     * script engine writes with its paths; the progress display has no
     * element of its own in the format. */
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
