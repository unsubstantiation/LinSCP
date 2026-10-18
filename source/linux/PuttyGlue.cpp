/*
 * PuttyGlue: the platform layer the shared PuTTY core expects from its
 * front end, for the POSIX build.
 *
 * Three groups of functions live here:
 *
 *  1. The MPEXT callback-set seam. The fork's core was built for
 *     upstream's Windows front end, where every SSH session owns a
 *     `struct callback_set' reached through get_callback_set() and
 *     get_seat_callback_set() (MPEXT means "one callback queue per
 *     session"). The console client has a single session, so all of
 *     these return one statically allocated set; the vendored POSIX
 *     platform layer reaches it through linscp_posix_callback_set().
 *
 *  2. Persistent storage (storage.h): saved sessions, the SSH host key
 *     cache and the random seed file, as plain files below the
 *     configuration directory.
 *
 *  3. The SFTP transport (sftp_senddata/sftp_recvdata/sftp_sendbuffer),
 *     which simply forwards to the session that is currently open.
 */

#include "Console.h"
#include "LocalFs.h"
#include "PathUtil.h"
#include "Session.h"
#include "Texts.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "PuttyCompat.h"

/*
 * storage.h declares these as opaque; here is what they are on POSIX.
 * They must be defined at global scope so that they complete the C typedefs
 * rather than shadowing them.
 */
struct settings_r
{
    std::vector<std::string> keys;
    std::vector<std::string> values;
};

struct settings_w
{
    std::string path;
    std::string contents;
};

struct host_ca_enum
{
    size_t index;
};

namespace {

/* ----------------------------------------------------------------------
 * Configuration directory
 */

std::string StorageRoot()
{
    const char * overrideDir = getenv("LINSCP_CONFIG_DIR");
    if (overrideDir != NULL && overrideDir[0] != '\0')
    {
        return std::string(overrideDir);
    }
    const char * xdg = getenv("XDG_CONFIG_HOME");
    if (xdg != NULL && xdg[0] != '\0')
    {
        return std::string(xdg) + "/LinSCP";
    }
    const char * home = getenv("HOME");
    if (home != NULL && home[0] != '\0')
    {
        return std::string(home) + "/.config/LinSCP";
    }
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "/tmp/LinSCP-%u",
        static_cast<unsigned int>(getuid()));
    return std::string(buffer);
}

bool MakeDirectoryTree(const std::string & path)
{
    std::string built;
    for (size_t i = 0; i < path.size(); i++)
    {
        built += path[i];
        if (path[i] == '/' && i > 0)
        {
            mkdir(built.c_str(), 0700);
        }
    }
    if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST)
    {
        return false;
    }
    return true;
}

std::string StoragePath(const std::string & name)
{
    return StorageRoot() + "/" + name;
}

std::string HostKeyPath()
{
    return StoragePath("sshhostkeys");
}

std::string RandomSeedPath()
{
    return StoragePath("randomseed");
}

/* Session names are used as file names, so '/' cannot appear in them. */
std::string EscapeSessionName(const char * name)
{
    std::string result;
    for (const char * p = name; *p != '\0'; p++)
    {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_')
        {
            result += *p;
        }
        else
        {
            char buffer[8];
            snprintf(buffer, sizeof(buffer), "%%%02X",
                static_cast<unsigned int>(static_cast<unsigned char>(*p)));
            result += buffer;
        }
    }
    return result;
}

bool ReadFile(const std::string & path, std::vector<char> & contents)
{
    contents.clear();
    FILE * file = fopen(path.c_str(), "rb");
    if (file == NULL)
    {
        return false;
    }
    char buffer[4096];
    size_t read;
    while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        contents.insert(contents.end(), buffer, buffer + read);
    }
    fclose(file);
    return true;
}

bool ReadLines(const std::string & path, std::vector<std::string> & lines)
{
    std::vector<char> contents;
    if (!ReadFile(path, contents))
    {
        return false;
    }
    std::string line;
    for (size_t i = 0; i < contents.size(); i++)
    {
        if (contents[i] == '\n')
        {
            lines.push_back(line);
            line.clear();
        }
        else if (contents[i] != '\r')
        {
            line += contents[i];
        }
    }
    if (!line.empty())
    {
        lines.push_back(line);
    }
    return true;
}

bool WriteFile(const std::string & path, const std::string & contents)
{
    MakeDirectoryTree(StorageRoot());
    FILE * file = fopen(path.c_str(), "wb");
    if (file == NULL)
    {
        return false;
    }
    if (!contents.empty())
    {
        if (fwrite(contents.data(), 1, contents.size(), file) != contents.size())
        {
            fclose(file);
            return false;
        }
    }
    fclose(file);
    chmod(path.c_str(), 0600);
    return true;
}

/* ----------------------------------------------------------------------
 * Saved sessions
 */

std::string SessionPath(const char * name)
{
    return StoragePath("sessions/") + EscapeSessionName(name);
}

/* ----------------------------------------------------------------------
 * UTF-8 conversions for BinarySink_put_mb_to_wc / put_wc_to_mb
 *
 * The core's own platform implementation understands a whole list of
 * code pages; this front end works in UTF-8, which is both CP_UTF8 and
 * the default code page.
 */

bool IsUtf8CodePage(int codepage)
{
    return codepage == CP_UTF8 || codepage == DEFAULT_CODEPAGE || codepage == -1;
}

void PutUtf8(BinarySink * bs, unsigned long value)
{
    char buffer[8];
    size_t len = 0;
    if (value < 0x80)
    {
        buffer[len++] = static_cast<char>(value);
    }
    else if (value < 0x800)
    {
        buffer[len++] = static_cast<char>(0xC0 | (value >> 6));
        buffer[len++] = static_cast<char>(0x80 | (value & 0x3F));
    }
    else if (value < 0x10000)
    {
        buffer[len++] = static_cast<char>(0xE0 | (value >> 12));
        buffer[len++] = static_cast<char>(0x80 | ((value >> 6) & 0x3F));
        buffer[len++] = static_cast<char>(0x80 | (value & 0x3F));
    }
    else
    {
        buffer[len++] = static_cast<char>(0xF0 | (value >> 18));
        buffer[len++] = static_cast<char>(0x80 | ((value >> 12) & 0x3F));
        buffer[len++] = static_cast<char>(0x80 | ((value >> 6) & 0x3F));
        buffer[len++] = static_cast<char>(0x80 | (value & 0x3F));
    }
    put_data(bs, buffer, len);
}

} // namespace

/* ======================================================================
 * Private key files
 * ==================================================================== */

/*
 * The SSH core only ever opens PuTTY .ppk files (and public key files) in
 * its user authentication code; the OpenSSH "new format" and old PEM keys
 * that every Linux user actually has are understood only by the importer
 * that PuTTY's conversion tools use. So a foreign key file is imported
 * here and written out as an unencrypted .ppk (mode 0600) below the
 * configuration directory for the core to read.
 */

namespace linscp {

namespace {

const char * const ImportedKeyPrefix = "imported-key-";

std::string gImportedKeyPath;

void DeleteImportedKeyFile()
{
    if (!gImportedKeyPath.empty())
    {
        remove(gImportedKeyPath.c_str());
        gImportedKeyPath.clear();
    }
}

/*
 * A key file left behind by a process that died before it could remove it
 * (the file name carries the process ID). Only files whose process is gone
 * are removed, so a converted key that another running client is still
 * using stays where it is.
 */
void DeleteStaleImportedKeyFiles()
{
    const std::string dir = StorageRoot();
    DIR * handle = opendir(dir.c_str());
    if (handle == NULL)
    {
        return;
    }
    const size_t prefixLength = strlen(ImportedKeyPrefix);
    struct dirent * entry;
    while ((entry = readdir(handle)) != NULL)
    {
        const std::string name(entry->d_name);
        if (name.compare(0, prefixLength, ImportedKeyPrefix) != 0)
        {
            continue;
        }
        const std::string::size_type dash = name.find_last_of('-');
        const std::string::size_type dot = name.rfind(".ppk");
        if (dash == std::string::npos || dot == std::string::npos || dot < dash)
        {
            continue;
        }
        const std::string pidText = name.substr(dash + 1, dot - dash - 1);
        if (pidText.empty())
        {
            continue;
        }
        char * end = NULL;
        const long pid = strtol(pidText.c_str(), &end, 10);
        if (end == NULL || *end != '\0' || pid <= 0)
        {
            continue;
        }
        if (kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM)
        {
            continue; /* still in use */
        }
        remove((dir + "/" + name).c_str());
    }
    closedir(handle);
}

/* Strips the surrounding white space and any line break of a key comment. */
std::string Trimmed(const char * text)
{
    if (text == NULL)
    {
        return std::string();
    }
    std::string result = text;
    while (!result.empty() &&
        (result[result.size() - 1] == '\n' || result[result.size() - 1] == '\r' ||
         result[result.size() - 1] == ' ' || result[result.size() - 1] == '\t'))
    {
        result.erase(result.size() - 1);
    }
    size_t start = result.find_first_not_of(" \t");
    return start == std::string::npos ? std::string() : result.substr(start);
}

/* Base64 of a key blob on one line, as authorized_keys wants it. */
std::string Base64OneLine(ptrlen data)
{
    strbuf * encoded = base64_encode_sb(data, 0);
    const std::string result(encoded->s, encoded->len);
    strbuf_free(encoded);
    return result;
}

} // namespace

std::string PreparePrivateKeyFile(const std::string & keyFile,
    std::string & error, const std::string & suppliedPassphrase)
{
    error.clear();
    DeleteImportedKeyFile();
    DeleteStaleImportedKeyFiles();
    if (keyFile.empty())
    {
        return std::string();
    }

    Filename * fileName = filename_from_str(keyFile.c_str());
    const int type = key_type(fileName);

    /*
     * PuTTY key files (with or without the private half) are read by the
     * core itself, so they need no conversion.
     */
    if (type == SSH_KEYTYPE_SSH2 || type == SSH_KEYTYPE_SSH2_PUBLIC_RFC4716 ||
        type == SSH_KEYTYPE_SSH2_PUBLIC_OPENSSH || type == SSH_KEYTYPE_SSH1 ||
        type == SSH_KEYTYPE_SSH1_PUBLIC)
    {
        filename_free(fileName);
        return keyFile;
    }
    if (!import_possible(type))
    {
        error = "Cannot use the private key file '" + keyFile + "': " +
            key_type_to_str(type) + ".";
        filename_free(fileName);
        return std::string();
    }

    /* An encrypted key needs its passphrase before it can be imported.
     * (import_encrypted writes a key comment out through this pointer
     * without a NULL check, so it must always be a real variable.) */
    std::string passphrase = suppliedPassphrase;
    char * keyComment = NULL;
    const bool encrypted = import_encrypted(fileName, type, &keyComment);
    sfree(keyComment);
    if (encrypted && passphrase.empty())
    {
        if (!Console::Instance().IsInteractive())
        {
            error = "The private key file '" + keyFile + "' is encrypted; "
                "supply -passphrase=<passphrase> or run interactively to "
                "enter its passphrase.";
            filename_free(fileName);
            return std::string();
        }
        if (!Console::Instance().ReadPassword(
                linscp::Texts::Translate("Passphrase for key file '{path}': ", {{"path", keyFile}}), passphrase) ||
            passphrase.empty())
        {
            error = "No passphrase given for the private key file '" + keyFile + "'.";
            filename_free(fileName);
            return std::string();
        }
    }

    /* Importing hashes the key and so needs the random pool, which the
     * SSH backend would only set up later. */
    random_ref();
    const char * importError = NULL;
    ssh2_userkey * key = import_ssh2(fileName, type,
        passphrase.empty() ? NULL : &passphrase[0], &importError);
    if (!passphrase.empty())
    {
        smemclr(&passphrase[0], passphrase.size());
    }
    filename_free(fileName);
    random_unref();

    if (key == NULL || key == SSH2_WRONG_PASSPHRASE)
    {
        error = "Cannot read the private key file '" + keyFile + "'";
        error += (key == SSH2_WRONG_PASSPHRASE) ? ": wrong passphrase." :
            (importError != NULL ? std::string(": ") + importError : ".");
        return std::string();
    }

    if (!MakeDirectoryTree(StorageRoot()))
    {
        error = "Cannot create the configuration directory '" + StorageRoot() + "'.";
        ssh_key_free(key->key);
        sfree(key->comment);
        sfree(key);
        return std::string();
    }

    char suffix[32];
    snprintf(suffix, sizeof(suffix), "-%u.ppk", static_cast<unsigned int>(getpid()));
    const std::string importedPath = StoragePath("imported-key" + std::string(suffix));
    Filename * imported = filename_from_str(importedPath.c_str());
    random_ref();
    const bool written = ppk_save_f(imported, key, NULL, &ppk_save_default_parameters);
    random_unref();
    filename_free(imported);
    ssh_key_free(key->key);
    sfree(key->comment);
    sfree(key);
    if (!written)
    {
        error = "Cannot write the converted private key file '" + importedPath + "'.";
        return std::string();
    }

    gImportedKeyPath = importedPath;
    Console::Instance().LogEvent(Texts::Translate(
        "Imported the {type} key file '{path}' as a PuTTY key file.",
        {{"type", std::string(key_type_to_str(type))}, {"path", keyFile}}));
    return importedPath;
}

void DiscardImportedPrivateKeyFile()
{
    DeleteImportedKeyFile();
}

/*
 * Reads the public half of 'keyFile' and formats it the way an OpenSSH
 * authorized_keys line looks ('algorithm base64 comment'). 'copyid' installs
 * exactly this text on the server, so the answer must not depend on the key
 * file format: a PuTTY private or public key file, an OpenSSH public key and
 * an OpenSSH private key (old PEM or the new format) all work, the last one
 * through the same importer the SSH core needs.
 */
bool PublicKeyAuthorizedLine(const std::string & keyFile, std::string & line,
    std::string & error, const std::string & suppliedPassphrase)
{
    line.clear();
    error.clear();

    const std::string path = ExpandTilde(keyFile);
    if (path.empty())
    {
        error = "No private key file was given.";
        return false;
    }

    Filename * fileName = filename_from_str(path.c_str());
    const int type = key_type(fileName);
    bool ok = false;

    if (type == SSH_KEYTYPE_SSH2_PUBLIC_OPENSSH)
    {
        /* Already a line of the right shape; take the first non-empty one. */
        FILE * file = fopen(path.c_str(), "rb");
        if (file == NULL)
        {
            error = "Cannot read the public key file '" + path + "': " +
                LastSystemError();
            filename_free(fileName);
            return false;
        }
        char buffer[8192];
        while (fgets(buffer, sizeof(buffer), file) != NULL)
        {
            std::string text = Trimmed(buffer);
            if (text.empty())
            {
                continue;
            }
            const size_t firstSpace = text.find(' ');
            const bool looksLikeKey = text.compare(0, 4, "ssh-") == 0 ||
                text.compare(0, 6, "ecdsa-") == 0 ||
                text.compare(0, 7, "sk-ssh-") == 0 ||
                text.compare(0, 9, "sk-ecdsa-") == 0;
            if (firstSpace == std::string::npos || !looksLikeKey)
            {
                error = "'" + path + "' is not an OpenSSH public key line.";
                break;
            }
            line = text;
            ok = true;
            break;
        }
        fclose(file);
        if (!ok && error.empty())
        {
            error = "No public key found in '" + path + "'.";
        }
        filename_free(fileName);
        return ok;
    }

    if (type == SSH_KEYTYPE_SSH2)
    {
        /* A PuTTY key file, with or without the private half. */
        char * algorithm = NULL;
        char * comment = NULL;
        const char * loadError = NULL;
        strbuf * blob = strbuf_new();
        if (ppk_loadpub_f(fileName, &algorithm, BinarySink_UPCAST(blob),
            &comment, &loadError))
        {
            line = std::string(algorithm != NULL ? algorithm : "") + " " +
                Base64OneLine(ptrlen_from_strbuf(blob));
            const std::string text = Trimmed(comment != NULL ? comment : "");
            if (!text.empty())
            {
                line += " " + text;
            }
            ok = true;
        }
        else
        {
            error = "Cannot read the public half of the key file '" + path +
                "': " + (loadError != NULL ? loadError : "unusable key file") + ".";
        }
        strbuf_free(blob);
        sfree(algorithm);
        sfree(comment);
        filename_free(fileName);
        return ok;
    }

    if (type == SSH_KEYTYPE_SSH1 || type == SSH_KEYTYPE_SSH1_PUBLIC ||
        !import_possible(type))
    {
        error = "Cannot use the key file '" + path + "': " +
            key_type_to_str(type) + ". Only SSH-2 keys can be installed.";
        filename_free(fileName);
        return false;
    }

    /*
     * A foreign private key. An encrypted one needs its passphrase first,
     * exactly as PreparePrivateKeyFile() requires, and a passphrase prompt
     * needs a terminal.
     */
    std::string passphrase = suppliedPassphrase;
    char * keyComment = NULL;
    const bool encrypted = import_encrypted(fileName, type, &keyComment);
    sfree(keyComment);
    if (encrypted && passphrase.empty())
    {
        if (!Console::Instance().IsInteractive())
        {
            error = "The private key file '" + path + "' is encrypted; supply "
                "-passphrase=<passphrase> or run interactively to enter its "
                "passphrase.";
            filename_free(fileName);
            return false;
        }
        if (!Console::Instance().ReadPassword(
                linscp::Texts::Translate("Passphrase for key file '{path}': ", {{"path", path}}), passphrase) ||
            passphrase.empty())
        {
            error = "No passphrase given for the private key file '" + path + "'.";
            filename_free(fileName);
            return false;
        }
    }

    random_ref();
    const char * importError = NULL;
    ssh2_userkey * key = import_ssh2(fileName, type,
        passphrase.empty() ? NULL : &passphrase[0], &importError);
    if (!passphrase.empty())
    {
        smemclr(&passphrase[0], passphrase.size());
    }
    filename_free(fileName);
    if (key == NULL || key == SSH2_WRONG_PASSPHRASE)
    {
        random_unref();
        error = "Cannot read the private key file '" + path + "'";
        error += (key == SSH2_WRONG_PASSPHRASE) ? ": wrong passphrase." :
            (importError != NULL ? std::string(": ") + importError : ".");
        return false;
    }

    strbuf * blob = strbuf_new();
    ssh_key_public_blob(key->key, BinarySink_UPCAST(blob));
    line = std::string(ssh_key_ssh_id(key->key)) + " " +
        Base64OneLine(ptrlen_from_strbuf(blob));
    strbuf_free(blob);
    const std::string text = Trimmed(key->comment != NULL ? key->comment : "");
    if (!text.empty())
    {
        line += " " + text;
    }
    random_unref();
    ssh_key_free(key->key);
    sfree(key->comment);
    sfree(key);
    return true;
}

} // namespace linscp

/* ======================================================================
 * C entry points expected by the core
 * ==================================================================== */

extern "C" {

/* --- 1. The MPEXT callback-set seam ---------------------------------- */

struct callback_set * linscp_posix_callback_set(void)
{
    static struct callback_set callbackSet;
    static bool initialised = false;
    if (!initialised)
    {
        memset(&callbackSet, 0, sizeof(callbackSet));
        linscp_critical_section_init(&callbackSet.ready_critsec[0]);
        initialised = true;
    }
    return &callbackSet;
}

struct callback_set * get_callback_set(Plug * plug)
{
    return linscp_posix_callback_set();
}

struct callback_set * get_seat_callback_set(Seat * seat)
{
    return linscp_posix_callback_set();
}

struct callback_set * get_log_callback_set(LogContext * ctx)
{
    return linscp_posix_callback_set();
}

Seat * get_log_seat(LogContext * ctx)
{
    linscp::Session * session = linscp::CurrentSession();
    return session != NULL ? static_cast<Seat *>(session->SeatHandle()) : NULL;
}

/* Protects the random pool and the bignum code; see platform.h. The
 * critical sections must be recursive (sshrand.c re-enters the section
 * from the noise callback), so they are set up here rather than with a
 * static initialiser. */
CRITICAL_SECTION putty_section;

/* One-time setup of the recursive mutex type, before main() does anything
 * that could take a section. */
void linscp_platform_init(void)
{
    linscp_critical_section_init(&putty_section);
}

} /* extern "C" */

namespace {

pthread_mutexattr_t g_criticalSectionAttr;
bool g_criticalSectionAttrReady = false;

const pthread_mutexattr_t & CriticalSectionAttributes()
{
    if (!g_criticalSectionAttrReady)
    {
        pthread_mutexattr_init(&g_criticalSectionAttr);
        pthread_mutexattr_settype(&g_criticalSectionAttr, PTHREAD_MUTEX_RECURSIVE);
        g_criticalSectionAttrReady = true;
    }
    return g_criticalSectionAttr;
}

} // namespace

extern "C" {

void linscp_critical_section_init(CRITICAL_SECTION * cs)
{
    pthread_mutex_init(cs, &CriticalSectionAttributes());
}

void linscp_critical_section_enter(CRITICAL_SECTION * cs)
{
    pthread_mutex_lock(cs);
}

void linscp_critical_section_leave(CRITICAL_SECTION * cs)
{
    pthread_mutex_unlock(cs);
}

/* The SSH local version string, sent in the version exchange. Upstream
 * provides it in utils/version.c, which FORK_BUILD leaves out, so the
 * front end provides it. ssh.h declares it without 'const' when MPEXT is
 * set. */
char sshver[] = "LinSCP-1.0";

/* Connection sharing is supported by the vendored unix/sharing.c. */
const bool share_can_be_upstream = true;
const bool share_can_be_downstream = true;

NORETURN void modalfatalbox(const char * format, ...)
{
    va_list args;
    va_start(args, format);
    char buffer[2048];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    linscp::Console::Instance().Fatal(buffer);
    exit(1);
}

/* timing.c announces the next timer through this; cliloop.c recomputes the
 * timers on every iteration of the main loop, so there is nothing to do. */
void timer_change_notify(unsigned long next)
{
}

void ldisc_echoedit_update(Ldisc * ldisc)
{
    /* No terminal discipline is used: there is no interactive shell. */
}

const char * in_memory_key_data(const Filename * fn)
{
    /* No private key is embedded in this binary. */
    (void)fn;
    return NULL;
}

void old_keyfile_warning(void)
{
    linscp::Console::Instance().Error(linscp::Texts::Translate(
        "Warning: this private key is in an old format; consider converting it."));
}

/* --- 2. Persistent storage ------------------------------------------- */

settings_r * open_settings_r(const char * name)
{
    if (name == NULL)
    {
        return NULL;
    }
    std::vector<std::string> lines;
    if (!ReadLines(SessionPath(name), lines))
    {
        return NULL;
    }
    settings_r * handle = new settings_r();
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string::size_type pos = lines[i].find('=');
        if (pos == std::string::npos)
        {
            continue;
        }
        handle->keys.push_back(lines[i].substr(0, pos));
        handle->values.push_back(lines[i].substr(pos + 1));
    }
    return handle;
}

void close_settings_r(settings_r * handle)
{
    delete handle;
}

char * read_setting_s(settings_r * handle, const char * key)
{
    if (handle == NULL)
    {
        return NULL;
    }
    for (size_t i = 0; i < handle->keys.size(); i++)
    {
        if (handle->keys[i] == key)
        {
            return dupstr(handle->values[i].c_str());
        }
    }
    return NULL;
}

int read_setting_i(settings_r * handle, const char * key, int defvalue)
{
    char * value = read_setting_s(handle, key);
    if (value == NULL)
    {
        return defvalue;
    }
    int result = atoi(value);
    sfree(value);
    return result;
}

Filename * read_setting_filename(settings_r * handle, const char * key)
{
    char * value = read_setting_s(handle, key);
    if (value == NULL)
    {
        return NULL;
    }
    Filename * result = filename_from_str(value);
    sfree(value);
    return result;
}

FontSpec * read_setting_fontspec(settings_r * handle, const char * key)
{
    /* Font settings are meaningless on this platform. */
    return NULL;
}

settings_w * open_settings_w(const char * name, char ** errmsg)
{
    if (errmsg != NULL)
    {
        *errmsg = NULL;
    }
    if (name == NULL)
    {
        return NULL;
    }
    MakeDirectoryTree(StoragePath("sessions"));
    settings_w * handle = new settings_w();
    handle->path = SessionPath(name);
    return handle;
}

void write_setting_s(settings_w * handle, const char * key, const char * value)
{
    if (handle == NULL)
    {
        return;
    }
    handle->contents += key;
    handle->contents += "=";
    handle->contents += (value != NULL ? value : "");
    handle->contents += "\n";
}

void write_setting_i(settings_w * handle, const char * key, int value)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%d", value);
    write_setting_s(handle, key, buffer);
}

void write_setting_filename(settings_w * handle, const char * key, Filename * value)
{
    write_setting_s(handle, key, value != NULL ? filename_to_str(value) : NULL);
}

void write_setting_fontspec(settings_w * handle, const char * key, FontSpec * font)
{
    /* Nothing to store: see read_setting_fontspec. */
}

void close_settings_w(settings_w * handle)
{
    if (handle == NULL)
    {
        return;
    }
    WriteFile(handle->path, handle->contents);
    delete handle;
}

/* --- SSH host key cache ---------------------------------------------- */

static std::string HostKeyPrefix(const char * hostname, int port)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%d", port);
    return std::string(hostname) + "@" + buffer;
}

static bool IsSpaceOrTab(char c)
{
    return c == ' ' || c == '\t';
}

/*
 * Parses a cache line, which reads
 *
 *     <hostname>@<port> <key type> <key>
 *
 * where <key> may itself contain no spaces but is otherwise opaque.
 * Returns false for a line that does not belong to this host and port
 * ('example.com@22' must not match a line for 'example.com@222'), or one
 * that is malformed. The separators are runs of spaces/tabs, so the
 * leading blank after the prefix is not mistaken for an empty key type.
 */
bool ParseHostKeyLine(const std::string & line, const std::string & prefix,
    std::string & type, std::string & value)
{
    if (line.size() <= prefix.size() ||
        line.compare(0, prefix.size(), prefix) != 0 ||
        !IsSpaceOrTab(line[prefix.size()]))
    {
        return false;
    }
    const std::string::size_type typeStart =
        line.find_first_not_of(" \t", prefix.size());
    if (typeStart == std::string::npos)
    {
        return false;
    }
    const std::string::size_type typeEnd =
        line.find_first_of(" \t", typeStart);
    if (typeEnd == std::string::npos)
    {
        return false;
    }
    const std::string::size_type valueStart =
        line.find_first_not_of(" \t", typeEnd);
    if (valueStart == std::string::npos)
    {
        return false;
    }
    type = line.substr(typeStart, typeEnd - typeStart);
    value = line.substr(valueStart);
    return true;
}

/* Reads the cache for this host, port and key type. Returns 1 and fills
 * 'key' when an entry was found, 0 when there is none. */
int retrieve_host_key(const char * hostname, int port, const char * keytype,
    char * key, int maxlen)
{
    std::vector<std::string> lines;
    ReadLines(HostKeyPath(), lines);
    const std::string prefix = HostKeyPrefix(hostname, port);
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string type;
        std::string value;
        if (!ParseHostKeyLine(lines[i], prefix, type, value))
        {
            continue;
        }
        if (keytype != NULL && type != keytype)
        {
            continue;
        }
        if (key != NULL && maxlen > 0)
        {
            strncpy(key, value.c_str(), maxlen - 1);
            key[maxlen - 1] = '\0';
        }
        return 1;
    }
    return 0;
}

/*
 * The console client keeps the trust decision in its own hands (the
 * FORK_BUILD core always asks the Seat), so this is what
 * seat_confirm_ssh_host_key uses:
 *
 *   1  a cached key exists for this host/port/key type and equals 'key'
 *   0  no key is cached for this host
 *  -1  a cached key exists and differs from 'key'
 *
 * 'key' is the server key in the same text form store_host_key() saved.
 */
int linscp_check_cached_host_key(const char * hostname, int port,
    const char * keytype, const char * key)
{
    std::vector<std::string> lines;
    ReadLines(HostKeyPath(), lines);
    const std::string prefix = HostKeyPrefix(hostname, port);
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string type;
        std::string value;
        if (!ParseHostKeyLine(lines[i], prefix, type, value))
        {
            continue;
        }
        if (keytype != NULL && type != keytype)
        {
            continue;
        }
        return (key != NULL && value == key) ? 1 : -1;
    }
    return 0;
}

bool have_ssh_host_key(Seat * seat, const char * host, int port, const char * keytype)
{
    return retrieve_host_key(host, port, keytype, NULL, 0) != 0;
}

void store_host_key(Seat * seat, const char * hostname, int port,
    const char * keytype, const char * key)
{
    std::vector<std::string> lines;
    ReadLines(HostKeyPath(), lines);
    std::string prefix = HostKeyPrefix(hostname, port);
    std::string entry = prefix + " " + keytype + " " + key;
    bool replaced = false;
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string type;
        std::string value;
        if (ParseHostKeyLine(lines[i], prefix, type, value) && type == keytype)
        {
            lines[i] = entry;
            replaced = true;
        }
    }
    if (!replaced)
    {
        lines.push_back(entry);
    }
    std::string contents;
    for (size_t i = 0; i < lines.size(); i++)
    {
        contents += lines[i];
        contents += "\n";
    }
    WriteFile(HostKeyPath(), contents);
}

/* --- Trusted certification authorities ------------------------------- */

host_ca_enum * enum_host_ca_start(void)
{
    return new host_ca_enum();
}

bool enum_host_ca_next(host_ca_enum * handle, strbuf * out)
{
    /* No CA store on this platform yet. */
    return false;
}

void enum_host_ca_finish(host_ca_enum * handle)
{
    delete handle;
}

host_ca * host_ca_load(const char * name)
{
    return NULL;
}

/* --- Random seed ----------------------------------------------------- */

void read_random_seed(noise_consumer_t consumer)
{
    std::vector<char> contents;
    if (!ReadFile(RandomSeedPath(), contents))
    {
        return;
    }
    if (!contents.empty())
    {
        consumer(contents.data(), static_cast<int>(contents.size()));
    }
}

void write_random_seed(void * data, int len)
{
    if (len <= 0)
    {
        return;
    }
    WriteFile(RandomSeedPath(),
        std::string(static_cast<char *>(data), static_cast<size_t>(len)));
}

/* --- Platform defaults ----------------------------------------------- */

char * platform_default_s(const char * name)
{
    /* No platform overrides: the compiled-in defaults from conf.h win. */
    return NULL;
}

bool platform_default_b(const char * name, bool def)
{
    return def;
}

int platform_default_i(const char * name, int def)
{
    return def;
}

/* These must never return NULL: settings.c passes the result straight to
 * conf_set_filename()/conf_set_fontspec(), which copy it. An empty
 * Filename is the "no file" value (see filename_is_null). */
Filename * platform_default_filename(const char * name)
{
    if (strcmp(name, "LogFileName") == 0)
    {
        return filename_from_str("linscp.log");
    }
    return filename_from_str("");
}

FontSpec * platform_default_fontspec(const char * name)
{
    return fontspec_new_default();
}

/* --- Code page conversion -------------------------------------------- */

bool BinarySink_put_mb_to_wc(BinarySink * bs, int codepage, const char * mbstr, int mblen)
{
    if (mblen <= 0)
    {
        return true;
    }
    if (!IsUtf8CodePage(codepage))
    {
        return false;
    }
    int i = 0;
    while (i < mblen)
    {
        unsigned char first = static_cast<unsigned char>(mbstr[i]);
        int extra;
        unsigned long value;
        if (first < 0x80)
        {
            value = first;
            extra = 0;
        }
        else if ((first & 0xE0) == 0xC0)
        {
            value = first & 0x1F;
            extra = 1;
        }
        else if ((first & 0xF0) == 0xE0)
        {
            value = first & 0x0F;
            extra = 2;
        }
        else if ((first & 0xF8) == 0xF0)
        {
            value = first & 0x07;
            extra = 3;
        }
        else
        {
            value = 0xFFFD;
            extra = 0;
        }
        i++;
        for (int n = 0; n < extra && i < mblen; n++, i++)
        {
            unsigned char cont = static_cast<unsigned char>(mbstr[i]);
            if ((cont & 0xC0) != 0x80)
            {
                i--;
                break;
            }
            value = (value << 6) | (cont & 0x3F);
        }
        wchar_t wide = static_cast<wchar_t>(value);
        put_data(bs, &wide, sizeof(wide));
    }
    return true;
}

bool BinarySink_put_wc_to_mb(BinarySink * bs, int codepage, const wchar_t * wcstr,
    int wclen, const char * defchr)
{
    if (wclen <= 0)
    {
        return true;
    }
    if (!IsUtf8CodePage(codepage))
    {
        return false;
    }
    for (int i = 0; i < wclen; i++)
    {
        unsigned long value = static_cast<unsigned long>(wcstr[i]);
        if (value > 0x10FFFF)
        {
            if (defchr != NULL)
            {
                put_data(bs, defchr, strlen(defchr));
            }
            continue;
        }
        PutUtf8(bs, value);
    }
    return true;
}

/* --- 3. The SFTP transport ------------------------------------------- */

bool sftp_senddata(const char * data, size_t len)
{
    linscp::Session * session = linscp::CurrentSession();
    if (session == NULL)
    {
        return false;
    }
    return session->SendData(data, len);
}

size_t sftp_sendbuffer(void)
{
    linscp::Session * session = linscp::CurrentSession();
    if (session == NULL)
    {
        return 0;
    }
    return session->SendBufferSize();
}

bool sftp_recvdata(char * data, size_t len)
{
    linscp::Session * session = linscp::CurrentSession();
    if (session == NULL)
    {
        return false;
    }
    return session->ReceiveData(data, len);
}

} /* extern "C" */
