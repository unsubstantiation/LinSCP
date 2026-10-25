/*
 * Editor: the remote editing workflow of the 'edit' command.
 *
 *   stat the remote file  ->  download it to a private temporary file
 *   ->  run the editor  ->  compare the temporary file with the copy
 *   that was downloaded  ->  ask  ->  upload it back.
 *
 * The remote file is checked again after the editor exits: if somebody
 * else changed it in the meantime the upload asks first instead of
 * overwriting their change, and in a non-interactive run it fails.
 */

#include "Editor.h"

#include <cstdio>
#include <cstring>

#include <unistd.h>

#include "Console.h"
#include "LocalFs.h"
#include "PathUtil.h"
#include "Platform.h"
#include "Texts.h"

namespace linscp {

namespace {

std::string EnvironmentVariable(const char * name)
{
    const char * value = getenv(name);
    return value != NULL ? std::string(value) : std::string();
}

/* Replaces everything that is not a file name character, so that a
 * remote path such as '/etc/nginx/nginx.conf' becomes one safe local
 * name. */
std::string SanitizeForFileName(const std::string & text)
{
    std::string result;
    for (size_t i = 0; i < text.size(); i++)
    {
        const char c = text[i];
        const bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        result += safe ? c : '_';
    }
    if (result.size() > 64)
    {
        result = result.substr(result.size() - 64);
    }
    if (result.empty() || result == "." || result == "..")
    {
        result = "file";
    }
    return result;
}

} // namespace

bool LooksLikeText(const char * data, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        if (data[i] == '\0')
        {
            return false;
        }
    }
    return true;
}

namespace {

bool ReadWholeFile(const std::string & path, std::string & content)
{
    content.clear();
    FILE * file = fopen(path.c_str(), "rb");
    if (file == NULL)
    {
        return false;
    }
    char buffer[8192];
    size_t got = 0;
    while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        content.append(buffer, got);
    }
    const bool ok = ferror(file) == 0;
    fclose(file);
    return ok;
}

bool WriteWholeFile(const std::string & path, const std::string & content)
{
    FILE * file = fopen(path.c_str(), "wb");
    if (file == NULL)
    {
        return false;
    }
    const size_t written = content.empty() ? 0 :
        fwrite(content.data(), 1, content.size(), file);
    const bool ok = written == content.size() && fflush(file) == 0;
    fclose(file);
    return ok;
}


bool UsesPureCrlf(const std::string & bytes)
{
    bool sawCrlf = false;
    for (size_t i = 0; i < bytes.size(); i++)
    {
        if (bytes[i] == '\n')
        {
            if (i == 0 || bytes[i - 1] != '\r')
            {
                return false;
            }
            sawCrlf = true;
        }
    }
    return sawCrlf;
}

std::string ConvertNewlinesToLf(const std::string & bytes)
{
    std::string out;
    out.reserve(bytes.size());
    for (size_t i = 0; i < bytes.size(); i++)
    {
        if (bytes[i] == '\r')
        {
            if (i + 1 < bytes.size() && bytes[i + 1] == '\n')
            {
                continue;
            }
            out += '\n';
            continue;
        }
        out += bytes[i];
    }
    return out;
}

std::string ConvertNewlinesToCrlf(const std::string & bytes)
{
    std::string out;
    out.reserve(bytes.size() + 32);
    for (size_t i = 0; i < bytes.size(); i++)
    {
        if (bytes[i] == '\r')
        {
            out += "\r\n";
            if (i + 1 < bytes.size() && bytes[i + 1] == '\n')
            {
                i++;
            }
        }
        else if (bytes[i] == '\n')
        {
            out += "\r\n";
        }
        else
        {
            out += bytes[i];
        }
    }
    return out;
}

} // namespace

std::string NormalizeEditedText(const std::string & originalBytes,
    const std::string & editedBytes, const std::string & eolPolicy)
{
    if (!LooksLikeText(editedBytes.data(), editedBytes.size()))
    {
        return editedBytes;
    }
    const bool hadBom = HasUtf8Bom(originalBytes);
    const bool hasBom = HasUtf8Bom(editedBytes);
    std::string body = hasBom ? editedBytes.substr(3) : editedBytes;
    const std::string origBody = hadBom ? originalBytes.substr(3) : originalBytes;

    if (eolPolicy == "lf")
    {
        body = ConvertNewlinesToLf(body);
    }
    else if (eolPolicy == "crlf")
    {
        body = ConvertNewlinesToCrlf(body);
    }
    else if (UsesPureCrlf(origBody))
    {
        body = ConvertNewlinesToCrlf(body);
    }

    if (hadBom || hasBom)
    {
        return std::string("\xEF\xBB\xBF", 3) + body;
    }
    return body;
}

std::vector<std::string> ResolveEditorCommand(const std::string & configured,
    std::string & error)
{
    error.clear();
    std::string command = configured;
    if (command.empty())
    {
        const char * variables[] = { "LINSCP_EDITOR", "VISUAL", "EDITOR" };
        for (size_t i = 0; i < sizeof(variables) / sizeof(variables[0]); i++)
        {
            const std::string value = EnvironmentVariable(variables[i]);
            if (!value.empty())
            {
                command = value;
                break;
            }
        }
    }
    if (command.empty())
    {
        static const char * const candidates[] = {
            "editor", "nano", "vim", "vi", "emacs", "gedit", "kate", "code"
        };
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
        {
            if (!FindExecutableOnPath(candidates[i]).empty())
            {
                command = candidates[i];
                break;
            }
        }
    }
    if (command.empty())
    {
        error = "No editor is configured. Set the LINSCP_EDITOR, VISUAL or "
            "EDITOR variable, use 'option editor <command>', or install one of "
            "the common editors.";
        return std::vector<std::string>();
    }

    std::vector<std::string> words = SplitCommandLine(command);
    if (words.empty())
    {
        error = "The editor command '" + command + "' is empty.";
        return std::vector<std::string>();
    }
    if (words[0].find('/') == std::string::npos)
    {
        const std::string resolved = FindExecutableOnPath(words[0]);
        if (resolved.empty())
        {
            error = "The editor '" + words[0] + "' was not found. Set the "
                "LINSCP_EDITOR variable or 'option editor <command>' to the "
                "editor to use.";
            return std::vector<std::string>();
        }
        words[0] = resolved;
    }
    return words;
}

bool PrepareEditorTempFile(const std::string & remotePath, std::string & path,
    std::string & error)
{
    std::string root = TempDirectory();
    if (root.empty())
    {
        root = ConfigDirectory();
    }
    if (root.empty())
    {
        error = "There is no temporary or configuration directory for the "
            "editor file.";
        return false;
    }
    char suffix[32];
    snprintf(suffix, sizeof(suffix), "linscp-edit-%ld",
        static_cast<long>(getpid()));
    const std::string directory = root + "/." + suffix;
    std::string createError;
    if (!CreatePrivateDirectory(directory, createError))
    {
        error = createError;
        return false;
    }
    path = JoinLocalPath(directory, SanitizeForFileName(RemoteFileName(remotePath)));
    return true;
}

bool RemoteEditor::Edit(const std::string & remotePath, const EditOptions & options,
    bool confirmUpload, std::string & error)
{
    error.clear();

    LscpAttrs attrs = {};
    std::string remoteError;
    const int exists = mAccess.Stat(remotePath, attrs, remoteError);
    if (exists == LSCP_SFTP_STAT_ERROR)
    {
        error = remoteError.empty() ? std::string("Cannot read '") + remotePath + "'."
            : remoteError;
        return false;
    }
    if (exists == LSCP_SFTP_STAT_MISSING)
    {
        error = "There is no remote file '" + remotePath + "'.";
        return false;
    }
    if ((attrs.flags & LSCP_ATTR_PERMISSIONS) != 0 &&
        (attrs.permissions & 0040000) != 0)
    {
        error = "'" + remotePath + "' is a directory, and only files can be edited.";
        return false;
    }
    if ((attrs.flags & LSCP_ATTR_SIZE) != 0 && !options.force &&
        attrs.size > options.maxSize)
    {
        char buffer[512];
        snprintf(buffer, sizeof(buffer),
            "'%s' is %llu bytes, which is over the %llu byte limit of the "
            "editor. Raise it with 'option editmaxsize <bytes>' or use "
            "'edit -force'.",
            remotePath.c_str(), attrs.size, options.maxSize);
        error = buffer;
        return false;
    }
    const unsigned long remoteMtimeBefore =
        (attrs.flags & LSCP_ATTR_ACMODTIME) != 0 ? attrs.mtime : 0;

    std::string tempPath;
    if (!PrepareEditorTempFile(remotePath, tempPath, error))
    {
        return false;
    }
    RemoveLocalFile(tempPath, remoteError); /* ignore: it may not exist */

    if (mConsole != NULL)
    {
        mConsole->Status("Downloading '" + remotePath + "' for editing...");
    }
    if (mAccess.Download(remotePath, tempPath, true, error) != 0)
    {
        RemoveLocalFile(tempPath, remoteError);
        if (error.empty())
        {
            error = std::string("Cannot download '") + remotePath + "'.";
        }
        return false;
    }
    RestrictFileToUser(tempPath);

    const LocalFileInfo before = StatLocal(tempPath);
    std::string beforeBytes;
    ReadWholeFile(tempPath, beforeBytes);
    if (!options.force && !options.allowBinary)
    {
        const size_t checkLen = beforeBytes.size() < 8192 ?
            beforeBytes.size() : 8192;
        if (checkLen != 0 && !LooksLikeText(beforeBytes.data(), checkLen))
        {
            error = "'" + remotePath + "' does not look like a text file. Use "
                "'edit -force' to edit it anyway.";
            if (!options.keepTempFile)
            {
                RemoveLocalFile(tempPath, remoteError);
            }
            return false;
        }
    }

    std::vector<std::string> command = ResolveEditorCommand(options.editor, error);
    if (command.empty())
    {
        if (!options.keepTempFile)
        {
            RemoveLocalFile(tempPath, remoteError);
        }
        return false;
    }
    command.push_back(tempPath);

    if (mConsole != NULL)
    {
        mConsole->Status("Editing '" + tempPath + "'. Save and close the editor "
            "to upload the file back to '" + remotePath + "'.");
    }
    const int exitCode = RunInteractive(command, error);
    if (exitCode < 0)
    {
        if (!options.keepTempFile)
        {
            RemoveLocalFile(tempPath, remoteError);
        }
        if (error.empty())
        {
            error = std::string("Cannot run the editor '") + command[0] + "'.";
        }
        return false;
    }
    if (exitCode != 0)
    {
        /* A non-zero exit is a failed or aborted editor run: keep the
         * file, the user may have work in it. */
        error = "The editor exited with status " + std::to_string(exitCode) +
            "; '" + remotePath + "' was not changed. The local copy is kept at '" +
            tempPath + "'.";
        return false;
    }

    unsigned long expectedRemoteMtime = remoteMtimeBefore;
    std::string lastUploadedBytes = beforeBytes;

    auto uploadIfChanged = [&](bool & uploadedOut) -> bool
    {
        uploadedOut = false;
        const LocalFileInfo after = StatLocal(tempPath);
        if (!after.exists)
        {
            error = "The temporary file '" + tempPath + "' is gone; '" +
                remotePath + "' was not changed.";
            return false;
        }
        std::string editedBytes;
        if (!ReadWholeFile(tempPath, editedBytes))
        {
            error = "Cannot read the edited file '" + tempPath + "'.";
            return false;
        }
        if (!options.force && !options.allowBinary)
        {
            editedBytes = NormalizeEditedText(beforeBytes, editedBytes,
                options.eol);
        }
        if (editedBytes == lastUploadedBytes &&
            after.mtime == before.mtime && after.size == before.size)
        {
            return true;
        }
        if (editedBytes == lastUploadedBytes)
        {
            return true;
        }
        if (!WriteWholeFile(tempPath, editedBytes))
        {
            error = "Cannot write the normalized file '" + tempPath + "'.";
            return false;
        }

        /* The remote file may have changed while the editor was open. */
        LscpAttrs nowAttrs = {};
        std::string statError;
        const int stillThere = mAccess.Stat(remotePath, nowAttrs, statError);
        if (stillThere == LSCP_SFTP_STAT_ERROR)
        {
            error = statError.empty() ? std::string("Cannot re-read '") +
                remotePath + "'." : statError;
            return false;
        }
        if (stillThere == LSCP_SFTP_STAT_MISSING)
        {
            error = "'" + remotePath + "' no longer exists; the edited copy is "
                "kept at '" + tempPath + "'.";
            return false;
        }
        const unsigned long remoteMtimeNow =
            (nowAttrs.flags & LSCP_ATTR_ACMODTIME) != 0 ? nowAttrs.mtime : 0;
        if (expectedRemoteMtime != 0 && remoteMtimeNow != expectedRemoteMtime)
        {
            bool overwrite = false;
            if (confirmUpload && mConsole != NULL && mConsole->IsInteractive())
            {
                overwrite = mConsole->Confirm("'" + remotePath +
                    "' changed on the server while it was open in the editor. "
                    "Overwrite it with your changes?", false);
            }
            if (!overwrite)
            {
                error = "'" + remotePath + "' changed on the server while it was "
                    "being edited, so it was not overwritten. Your copy is kept at '" +
                    tempPath + "'.";
                return false;
            }
        }

        if (confirmUpload && mConsole != NULL && mConsole->IsInteractive() &&
            !mConsole->Confirm("Upload the changes to '" + remotePath + "'?", true))
        {
            if (mConsole != NULL)
            {
                mConsole->Status("Cancelled. The edited copy is kept at '" +
                    tempPath + "'.");
            }
            return true;
        }

        if (mConsole != NULL)
        {
            mConsole->Status("Uploading '" + remotePath + "'...");
        }
        if (mAccess.Upload(tempPath, remotePath, false, error) != 0)
        {
            if (error.empty())
            {
                error = std::string("Cannot upload '") + remotePath + "'.";
            }
            error += " The edited copy is kept at '" + tempPath + "'.";
            return false;
        }
        if (mConsole != NULL)
        {
            mConsole->Status("Uploaded '" + remotePath + "'.");
        }
        lastUploadedBytes = editedBytes;
        uploadedOut = true;
        LscpAttrs updatedAttrs = {};
        if (mAccess.Stat(remotePath, updatedAttrs, statError) ==
                LSCP_SFTP_STAT_EXISTS &&
            (updatedAttrs.flags & LSCP_ATTR_ACMODTIME) != 0)
        {
            expectedRemoteMtime = updatedAttrs.mtime;
        }
        return true;
    };

    bool uploaded = false;
    if (!uploadIfChanged(uploaded))
    {
        return false;
    }
    if (!uploaded && !options.monitor)
    {
        if (mConsole != NULL)
        {
            mConsole->Status("No changes to upload; '" + remotePath +
                "' is unchanged.");
        }
        if (!options.keepTempFile)
        {
            RemoveLocalFile(tempPath, remoteError);
        }
        return true;
    }

    if (options.monitor)
    {
        ClearInterrupt();
        InstallInterruptHandler();
        unsigned completedPasses = 0;
        const unsigned targetPasses = options.monitorPasses == 0 ? 1 :
            options.monitorPasses;
        if (mConsole != NULL)
        {
            mConsole->Status("Monitoring '" + tempPath + "' for local saves...");
        }
        unsigned elapsedPolls = 0;
        while (!Interrupted() && completedPasses < targetPasses)
        {
            SleepMilliseconds(options.monitorIntervalMs > 0 ?
                options.monitorIntervalMs : 50);
            bool passUploaded = false;
            if (!uploadIfChanged(passUploaded))
            {
                ClearInterrupt();
                return false;
            }
            if (passUploaded)
            {
                completedPasses++;
                elapsedPolls = 0;
            }
            else if (++elapsedPolls > 200)
            {
                break;
            }
        }
        ClearInterrupt();
    }

    if (!options.keepTempFile)
    {
        RemoveLocalFile(tempPath, remoteError);
    }
    return true;
}

/* ---- Non-UTF-8 encoding support -----------------------------------------
 *
 * The CLI 'edit' command can transcode files that are not in UTF-8.
 * The conversion uses iconv, which is part of glibc and musl (the C
 * libraries on every Linux distribution LinSCP targets).  Every byte
 * that cannot be represented in the target encoding produces an error
 * rather than a silent replacement, so a file is never overwritten
 * with corrupted bytes.
 */

bool HasUtf8Bom(const std::string & data)
{
    return data.size() >= 3 &&
        static_cast<unsigned char>(data[0]) == 0xEF &&
        static_cast<unsigned char>(data[1]) == 0xBB &&
        static_cast<unsigned char>(data[2]) == 0xBF;
}

bool IsValidUtf8(const std::string & data)
{
    size_t i = 0;
    /* Skip BOM */
    if (data.size() >= 3 &&
        static_cast<unsigned char>(data[0]) == 0xEF &&
        static_cast<unsigned char>(data[1]) == 0xBB &&
        static_cast<unsigned char>(data[2]) == 0xBF)
    {
        i = 3;
    }
    while (i < data.size())
    {
        unsigned char c = static_cast<unsigned char>(data[i]);
        unsigned int extra = 0;
        if (c <= 0x7F)
        {
            i++;
            continue;
        }
        else if ((c & 0xE0) == 0xC0) { extra = 1; }
        else if ((c & 0xF0) == 0xE0) { extra = 2; }
        else if ((c & 0xF8) == 0xF0) { extra = 3; }
        else
        {
            return false;
        }
        /* Check the first byte's range */
        if (extra == 1 && c < 0xC2) return false;
        if (extra == 3 && c > 0xF4) return false;
        if (i + extra >= data.size()) return false;
        for (unsigned int j = 1; j <= extra; j++)
        {
            unsigned char b = static_cast<unsigned char>(data[i + j]);
            if ((b & 0xC0) != 0x80) return false;
        }
        /* Check for overlong encodings */
        if (extra == 2)
        {
            unsigned char c2 = static_cast<unsigned char>(data[i + 1]);
            if (c == 0xE0 && c2 < 0xA0) return false;
            if (c == 0xED && c2 > 0x9F) return false;
        }
        if (extra == 3)
        {
            unsigned char c2 = static_cast<unsigned char>(data[i + 1]);
            if (c == 0xF0 && c2 < 0x90) return false;
            if (c == 0xF4 && c2 > 0x8F) return false;
        }
        i += 1 + extra;
    }
    return true;
}

/* iconv-based conversion: converts between any two encodings that the
 * platform's iconv recognizes.  Returns empty on error. */
namespace {

#include <iconv.h>

std::string IconvConvert(const std::string & data,
    const char * fromEnc, const char * toEnc, std::string & error)
{
    error.clear();
    iconv_t cd = iconv_open(toEnc, fromEnc);
    if (cd == reinterpret_cast<iconv_t>(-1))
    {
        error = std::string("iconv does not support conversion from '") +
            fromEnc + "' to '" + toEnc + "'.";
        return std::string();
    }
    std::string result;
    result.reserve(data.size() * 2);
    char * inBuf = const_cast<char *>(data.data());
    size_t inLeft = data.size();
    char outBuf[4096];
    while (inLeft > 0)
    {
        char * outPtr = outBuf;
        size_t outLeft = sizeof(outBuf);
        size_t rc = iconv(cd, &inBuf, &inLeft, &outPtr, &outLeft);
        if (outPtr > outBuf)
        {
            result.append(outBuf, outPtr - outBuf);
        }
        if (rc == static_cast<size_t>(-1))
        {
            if (errno == E2BIG)
            {
                /* Output buffer full; continue. */
                continue;
            }
            if (errno == EILSEQ)
            {
                error = "Invalid byte sequence for encoding '" +
                    std::string(fromEnc) + "'.";
                iconv_close(cd);
                return std::string();
            }
            if (errno == EINVAL)
            {
                error = "Incomplete byte sequence at end of input for encoding '" +
                    std::string(fromEnc) + "'.";
                iconv_close(cd);
                return std::string();
            }
            error = std::string("iconv conversion failed: ") + strerror(errno);
            iconv_close(cd);
            return std::string();
        }
    }
    /* Flush any shift-state reset sequence. */
    char * outPtr = outBuf;
    size_t outLeft = sizeof(outBuf);
    iconv(cd, NULL, NULL, &outPtr, &outLeft);
    if (outPtr > outBuf)
    {
        result.append(outBuf, outPtr - outBuf);
    }
    iconv_close(cd);
    return result;
}

} // namespace

std::string ConvertToUtf8(const std::string & data,
    const std::string & fromEncoding, std::string & error)
{
    return IconvConvert(data, fromEncoding.c_str(), "UTF-8", error);
}

std::string ConvertFromUtf8(const std::string & data,
    const std::string & toEncoding, std::string & error)
{
    return IconvConvert(data, "UTF-8", toEncoding.c_str(), error);
}

std::string ReadWithEncoding(const std::string & localPath,
    const std::string & encoding, std::string & detectedEncoding,
    std::string & error)
{
    detectedEncoding.clear();
    FILE * file = fopen(localPath.c_str(), "rb");
    if (!file)
    {
        error = std::string("Cannot open '") + localPath + "': " +
            strerror(errno);
        return std::string();
    }
    std::string data;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0)
    {
        data.append(buf, n);
    }
    fclose(file);

    /* UTF-8 mode or auto-detect */
    if (encoding.empty() || encoding == "utf-8")
    {
        detectedEncoding = "utf-8";
        if (HasUtf8Bom(data))
        {
            /* Strip the BOM for the editor. */
            return data.substr(3);
        }
        return data;
    }

    /* Convert from the given encoding. */
    detectedEncoding = encoding;
    std::string converted = ConvertToUtf8(data, encoding, error);
    if (converted.empty() && !error.empty())
    {
        return std::string();
    }
    return converted;
}

bool WriteWithEncoding(const std::string & localPath,
    const std::string & text, const std::string & encoding,
    std::string & error)
{
    std::string output;
    if (encoding.empty() || encoding == "utf-8")
    {
        output = text;
    }
    else
    {
        output = ConvertFromUtf8(text, encoding, error);
        if (output.empty() && !error.empty())
        {
            return false;
        }
    }

    FILE * file = fopen(localPath.c_str(), "wb");
    if (!file)
    {
        error = std::string("Cannot write '") + localPath + "': " +
            strerror(errno);
        return false;
    }
    size_t written = fwrite(output.data(), 1, output.size(), file);
    fclose(file);
    if (written != output.size())
    {
        error = std::string("Short write to '") + localPath + "'.";
        return false;
    }
    return true;
}

} // namespace linscp
