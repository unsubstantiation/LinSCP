/*
 * SftpClient: the SFTP (v3) protocol operations of the front end,
 * spoken directly over the SSH subsystem channel libssh opened for the
 * session (Session's SendData/ReceiveData). See SftpClient.h for the
 * plain C API the front end uses.
 *
 * Why not libssh's own SFTP client (sftp_new and friends)? Two reasons,
 * both about what is on the wire:
 *
 *   * The copy-data and check-file-name extensions have no libssh API,
 *     and this client uses them whenever the server offers them (the
 *     fallback is a copy or a hash through a stream, which the caller
 *     arranges on a -2 return).
 *   * A libssh sftp_open always carries a permissions attribute, and
 *     some servers apply it to the handle even for a read or for a file
 *     that already exists; speaking the protocol here is what lets a
 *     plain open carry no attributes, as the old client sent.
 *
 * The price is that this file is an SFTP client; it is a small one,
 * because the transport, authentication and host key policy all live
 * in Session/libssh, and only request/response bookkeeping lives here.
 */

#include "SftpClient.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include "Session.h"

#define TRANSFER_CHUNK 32768

/* SFTP v3 packet types. */
enum
{
    SSH_FXP_INIT = 1,
    SSH_FXP_VERSION = 2,
    SSH_FXP_OPEN = 3,
    SSH_FXP_CLOSE = 4,
    SSH_FXP_READ = 5,
    SSH_FXP_WRITE = 6,
    SSH_FXP_LSTAT = 7,
    SSH_FXP_SETSTAT = 9,
    SSH_FXP_OPENDIR = 11,
    SSH_FXP_READDIR = 12,
    SSH_FXP_REMOVE = 13,
    SSH_FXP_MKDIR = 14,
    SSH_FXP_RMDIR = 15,
    SSH_FXP_REALPATH = 16,
    SSH_FXP_STAT = 17,
    SSH_FXP_RENAME = 18,
    SSH_FXP_SYMLINK = 20,
    SSH_FXP_EXTENDED = 200,
    SSH_FXP_EXTENDED_REPLY = 201,
    SSH_FXP_STATUS = 101,
    SSH_FXP_HANDLE = 102,
    SSH_FXP_DATA = 103,
    SSH_FXP_NAME = 104,
    SSH_FXP_ATTRS = 105
};

/* SFTP v3 status codes. */
enum
{
    SSH_FX_OK = 0,
    SSH_FX_EOF = 1,
    SSH_FX_NO_SUCH_FILE = 2,
    SSH_FX_PERMISSION_DENIED = 3,
    SSH_FX_FAILURE = 4,
    SSH_FX_OP_UNSUPPORTED = 8
};

namespace {

char g_error[1024];
uint32_t g_next_id = 1;
int g_last_status = -1;
bool g_initialized = false;

void clear_error()
{
    g_error[0] = '\0';
}

void set_error(const char * text)
{
    snprintf(g_error, sizeof(g_error), "%s", text);
}

/* ---- packet building ------------------------------------------------ */

struct PacketBuilder
{
    std::vector<char> data;

    void byte(unsigned int value)
    {
        data.push_back(static_cast<char>(value & 0xff));
    }
    void u32(uint32_t value)
    {
        byte(value >> 24);
        byte(value >> 16);
        byte(value >> 8);
        byte(value);
    }
    void u64(uint64_t value)
    {
        u32(static_cast<uint32_t>(value >> 32));
        u32(static_cast<uint32_t>(value));
    }
    void str(const char * text, size_t length)
    {
        u32(static_cast<uint32_t>(length));
        data.insert(data.end(), text, text + length);
    }
    void str(const std::string & text)
    {
        str(text.data(), text.size());
    }
    void str(const char * text)
    {
        str(text, strlen(text));
    }
};

/* ---- packet parsing ------------------------------------------------- */

struct PacketReader
{
    const char * data;
    size_t length;
    size_t pos;
    bool ok;

    PacketReader(const char * d, size_t l) : data(d), length(l), pos(0), ok(true) {}

    unsigned int byte()
    {
        if (pos + 1 > length)
        {
            ok = false;
            return 0;
        }
        return static_cast<unsigned char>(data[pos++]);
    }
    uint32_t u32()
    {
        uint32_t value = 0;
        for (int i = 0; i < 4; i++)
        {
            value = (value << 8) | byte();
        }
        return value;
    }
    uint64_t u64()
    {
        const uint64_t hi = u32();
        const uint64_t lo = u32();
        return (hi << 32) | lo;
    }
    std::string str()
    {
        const uint32_t size = u32();
        if (!ok || size > length - pos)
        {
            ok = false;
            return std::string();
        }
        std::string result(data + pos, size);
        pos += size;
        return result;
    }
    void skip(size_t count)
    {
        if (count > length - pos)
        {
            ok = false;
            pos = length;
            return;
        }
        pos += count;
    }
};

/* Attributes, as parsed from an ATTRS or NAME packet. */
struct WireAttrs
{
    uint32_t flags;
    uint64_t size;
    uint32_t uid, gid;
    uint32_t permissions;
    uint32_t atime, mtime;

    WireAttrs() : flags(0), size(0), uid(0), gid(0), permissions(0),
        atime(0), mtime(0) {}
};

WireAttrs read_attrs(PacketReader & reader)
{
    WireAttrs attrs;
    attrs.flags = reader.u32();
    if (attrs.flags & LSCP_ATTR_SIZE)
    {
        attrs.size = reader.u64();
    }
    if (attrs.flags & LSCP_ATTR_UIDGID)
    {
        attrs.uid = reader.u32();
        attrs.gid = reader.u32();
    }
    if (attrs.flags & LSCP_ATTR_PERMISSIONS)
    {
        attrs.permissions = reader.u32();
    }
    if (attrs.flags & LSCP_ATTR_ACMODTIME)
    {
        attrs.atime = reader.u32();
        attrs.mtime = reader.u32();
    }
    if (attrs.flags & 0x80000000u) /* SSH_FILEXFER_ATTR_EXTENDED */
    {
        const uint32_t count = reader.u32();
        for (uint32_t i = 0; i < count && reader.ok; i++)
        {
            reader.str();
            reader.str();
        }
    }
    return attrs;
}

void write_attrs(PacketBuilder & packet, const WireAttrs & attrs)
{
    packet.u32(attrs.flags);
    if (attrs.flags & LSCP_ATTR_SIZE)
    {
        packet.u64(attrs.size);
    }
    if (attrs.flags & LSCP_ATTR_UIDGID)
    {
        packet.u32(attrs.uid);
        packet.u32(attrs.gid);
    }
    if (attrs.flags & LSCP_ATTR_PERMISSIONS)
    {
        packet.u32(attrs.permissions);
    }
    if (attrs.flags & LSCP_ATTR_ACMODTIME)
    {
        packet.u32(attrs.atime);
        packet.u32(attrs.mtime);
    }
}

void attrs_to_public(const WireAttrs & attrs, LscpAttrs * out)
{
    memset(out, 0, sizeof(*out));
    out->flags = attrs.flags & 0x0fu;
    out->size = attrs.size;
    out->uid = attrs.uid;
    out->gid = attrs.gid;
    out->permissions = attrs.permissions;
    out->atime = attrs.atime;
    out->mtime = attrs.mtime;
}

/* ---- transport ------------------------------------------------------ */

linscp::Session * current_session()
{
    return linscp::CurrentSession();
}

bool send_packet(const PacketBuilder & payload)
{
    linscp::Session * session = current_session();
    if (session == NULL)
    {
        set_error("Not connected to an SFTP server.");
        return false;
    }
    PacketBuilder frame;
    frame.u32(static_cast<uint32_t>(payload.data.size()));
    if (!session->SendData(frame.data.data(), frame.data.size()) ||
        !session->SendData(payload.data.data(), payload.data.size()))
    {
        set_error("Cannot write to the SSH connection.");
        return false;
    }
    return true;
}

bool receive_exact(char * buffer, size_t length)
{
    linscp::Session * session = current_session();
    if (session == NULL)
    {
        set_error("Not connected to an SFTP server.");
        return false;
    }
    if (!session->ReceiveData(buffer, length))
    {
        set_error("The connection has been closed by the server.");
        return false;
    }
    return true;
}

/* One whole response packet: type byte plus payload after it. */
bool receive_packet(unsigned int & type, std::vector<char> & payload)
{
    char header[4];
    if (!receive_exact(header, 4))
    {
        return false;
    }
    PacketReader lengthReader(header, 4);
    const uint32_t length = lengthReader.u32();
    if (length == 0 || length > (64u << 20))
    {
        set_error("Received an implausible SFTP packet from the server.");
        return false;
    }
    std::vector<char> packet(length);
    if (!receive_exact(packet.data(), packet.size()))
    {
        return false;
    }
    type = static_cast<unsigned char>(packet[0]);
    payload.assign(packet.begin() + 1, packet.end());
    return true;
}

/*
 * Sends one request and reads its response. On a STATUS response the
 * status code is in g_last_status and 'statusMessage' holds the text;
 * the caller decides whether that is an error. Returns false only when
 * the transport failed or the response was not for this request.
 */
bool request(unsigned int type, const PacketBuilder & body,
    unsigned int & responseType, std::vector<char> & response,
    std::string & statusMessage)
{
    statusMessage.clear();
    g_last_status = -1;
    PacketBuilder packet;
    packet.byte(type);
    const uint32_t id = g_next_id++;
    packet.u32(id);
    packet.data.insert(packet.data.end(), body.data.begin(), body.data.end());
    if (!send_packet(packet))
    {
        return false;
    }
    if (!receive_packet(responseType, response))
    {
        return false;
    }
    PacketReader reader(response.data(), response.size());
    if (responseType == SSH_FXP_STATUS)
    {
        const uint32_t responseId = reader.u32();
        if (!reader.ok || responseId != id)
        {
            set_error("Received a packet that does not belong to any request.");
            return false;
        }
        const uint32_t rawStatus = reader.u32();
        if (!reader.ok)
        {
            set_error("Received a truncated SFTP status packet.");
            return false;
        }
        g_last_status = static_cast<int>(rawStatus);
        /* SFTP v2 servers omit the message string in SSH_FXP_STATUS; keep
         * status valid even when no message follows. */
        if (reader.pos < reader.length)
        {
            statusMessage = reader.str();
        }
        return true;
    }
    const uint32_t responseId = reader.u32();
    if (!reader.ok || responseId != id)
    {
        set_error("Received a packet that does not belong to any request.");
        return false;
    }
    /* Re-expose the payload after the id. */
    response.erase(response.begin(),
        response.begin() + static_cast<ptrdiff_t>(reader.pos));
    return true;
}

const char * status_text(int status)
{
    switch (status)
    {
    case SSH_FX_OK: return "Ok";
    case SSH_FX_EOF: return "End of file";
    case SSH_FX_NO_SUCH_FILE: return "No such file";
    case SSH_FX_PERMISSION_DENIED: return "Permission denied";
    case SSH_FX_FAILURE: return "Failure";
    case SSH_FX_OP_UNSUPPORTED: return "Operation unsupported";
    default: return "SFTP error";
    }
}

void set_error_path(const char * what, const char * path,
    const std::string & statusMessage)
{
    snprintf(g_error, sizeof(g_error), "%s '%s': SFTP server: %s", what, path,
        !statusMessage.empty() ? statusMessage.c_str() :
            status_text(g_last_status));
}

void set_system_error(const char * what, const char * path)
{
    const int errorNumber = errno != 0 ? errno : EIO;
    snprintf(g_error, sizeof(g_error), "%s '%s': %s", what, path,
        strerror(errorNumber));
}

/* A request whose whole answer is a STATUS: 0 on OK, -1 otherwise. */
int simple_op(unsigned int type, const PacketBuilder & body,
    const char * what, const char * path)
{
    unsigned int responseType;
    std::vector<char> response;
    std::string statusMessage;
    if (!request(type, body, responseType, response, statusMessage))
    {
        return -1;
    }
    if (responseType != SSH_FXP_STATUS || g_last_status != SSH_FX_OK)
    {
        set_error_path(what, path, statusMessage);
        return -1;
    }
    return 0;
}

int close_handle(const std::string & handle)
{
    PacketBuilder body;
    body.str(handle);
    return simple_op(SSH_FXP_CLOSE, body, "Closing the handle", "");
}

/* Opens a handle: 0 on success (handle filled), -1 otherwise. */
int open_handle(const char * path, uint32_t access, const WireAttrs * attrs,
    std::string & handle, const char * what)
{
    PacketBuilder body;
    body.str(path);
    body.u32(access);
    if (attrs != NULL)
    {
        write_attrs(body, *attrs);
    }
    else
    {
        body.u32(0);
    }
    unsigned int responseType;
    std::vector<char> response;
    std::string statusMessage;
    if (!request(SSH_FXP_OPEN, body, responseType, response, statusMessage))
    {
        return -1;
    }
    if (responseType != SSH_FXP_HANDLE)
    {
        set_error_path(what, path, statusMessage);
        return -1;
    }
    PacketReader reader(response.data(), response.size());
    handle = reader.str();
    if (!reader.ok)
    {
        set_error("The server answered an open with a malformed handle.");
        return -1;
    }
    return 0;
}

} // namespace

extern "C" const char * lscp_sftp_error(void)
{
    return g_error;
}

extern "C" void lscp_sftp_cleanup(void)
{
    g_initialized = false;
    clear_error();
}

extern "C" int lscp_sftp_init(void)
{
    clear_error();
    if (current_session() == NULL)
    {
        set_error("Not connected to an SFTP server.");
        return -1;
    }
    if (g_initialized)
    {
        return 0;
    }
    /* SSH_FXP_INIT: version 3, no extensions offered by the client. */
    PacketBuilder packet;
    packet.byte(SSH_FXP_INIT);
    packet.u32(3);
    if (!send_packet(packet))
    {
        return -1;
    }
    unsigned int type;
    std::vector<char> response;
    if (!receive_packet(type, response))
    {
        return -1;
    }
    if (type != SSH_FXP_VERSION)
    {
        set_error("SFTP protocol initialisation failed: the server did "
            "not answer the initialisation packet.");
        return -1;
    }
    g_next_id = 1;
    g_initialized = true;
    return 0;
}

extern "C" char * lscp_sftp_realpath(const char * path)
{
    clear_error();
    PacketBuilder body;
    body.str(path);
    unsigned int responseType;
    std::vector<char> response;
    std::string statusMessage;
    if (!request(SSH_FXP_REALPATH, body, responseType, response,
            statusMessage))
    {
        return NULL;
    }
    if (responseType != SSH_FXP_NAME)
    {
        set_error_path("Resolving the path", path, statusMessage);
        return NULL;
    }
    PacketReader reader(response.data(), response.size());
    const uint32_t count = reader.u32();
    if (!reader.ok || count == 0)
    {
        set_error("The server answered a realpath with no name.");
        return NULL;
    }
    const std::string resolved = reader.str();
    if (!reader.ok)
    {
        set_error("The server answered a realpath with a malformed name.");
        return NULL;
    }
    return strdup(resolved.c_str());
}

extern "C" int lscp_sftp_stat(const char * path, LscpAttrs * attrs)
{
    clear_error();
    if (attrs != NULL)
    {
        memset(attrs, 0, sizeof(*attrs));
    }
    PacketBuilder body;
    body.str(path);
    unsigned int responseType;
    std::vector<char> response;
    std::string statusMessage;
    if (!request(SSH_FXP_STAT, body, responseType, response, statusMessage))
    {
        return LSCP_SFTP_STAT_ERROR;
    }
    if (responseType != SSH_FXP_ATTRS)
    {
        set_error_path("Getting the attributes of", path, statusMessage);
        return g_last_status == SSH_FX_NO_SUCH_FILE ?
            LSCP_SFTP_STAT_MISSING : LSCP_SFTP_STAT_ERROR;
    }
    PacketReader reader(response.data(), response.size());
    const WireAttrs wire = read_attrs(reader);
    if (!reader.ok)
    {
        set_error("The server answered a stat with malformed attributes.");
        return LSCP_SFTP_STAT_ERROR;
    }
    if (attrs != NULL)
    {
        attrs_to_public(wire, attrs);
    }
    return LSCP_SFTP_STAT_EXISTS;
}

extern "C" LscpNames * lscp_sftp_list_dir(const char * path)
{
    clear_error();
    std::string handle;
    {
        /* SSH_FXP_OPENDIR carries only the path, unlike SSH_FXP_OPEN. */
        PacketBuilder body;
        body.str(path);
        unsigned int responseType;
        std::vector<char> response;
        std::string statusMessage;
        if (!request(SSH_FXP_OPENDIR, body, responseType, response,
                statusMessage))
        {
            return NULL;
        }
        if (responseType != SSH_FXP_HANDLE)
        {
            set_error_path("Opening the directory", path, statusMessage);
            return NULL;
        }
        PacketReader reader(response.data(), response.size());
        handle = reader.str();
        if (!reader.ok)
        {
            set_error("The server answered an opendir with a malformed handle.");
            return NULL;
        }
    }

    LscpNames * result = static_cast<LscpNames *>(
        calloc(1, sizeof(LscpNames)));
    std::vector<LscpName> entries;
    bool failed = false;
    for (;;)
    {
        PacketBuilder body;
        body.str(handle);
        unsigned int responseType;
        std::vector<char> response;
        std::string statusMessage;
        if (!request(SSH_FXP_READDIR, body, responseType, response,
                statusMessage))
        {
            failed = true;
            break;
        }
        if (responseType == SSH_FXP_STATUS)
        {
            if (g_last_status == SSH_FX_EOF)
            {
                break;
            }
            set_error_path("Reading the directory", path, statusMessage);
            failed = true;
            break;
        }
        if (responseType != SSH_FXP_NAME)
        {
            set_error_path("Reading the directory", path, statusMessage);
            failed = true;
            break;
        }
        PacketReader reader(response.data(), response.size());
        const uint32_t count = reader.u32();
        for (uint32_t i = 0; i < count && reader.ok; i++)
        {
            LscpName entry;
            memset(&entry, 0, sizeof(entry));
            const std::string filename = reader.str();
            const std::string longname = reader.str();
            const WireAttrs wire = read_attrs(reader);
            entry.filename = strdup(filename.c_str());
            entry.longname = strdup(longname.c_str());
            attrs_to_public(wire, &entry.attrs);
            entries.push_back(entry);
        }
        if (!reader.ok)
        {
            set_error("The server answered a readdir with malformed names.");
            failed = true;
            break;
        }
        if (count == 0)
        {
            break;
        }
    }
    close_handle(handle);
    if (failed)
    {
        for (size_t i = 0; i < entries.size(); i++)
        {
            free(entries[i].filename);
            free(entries[i].longname);
        }
        free(result);
        return NULL;
    }
    result->count = static_cast<int>(entries.size());
    if (!entries.empty())
    {
        result->names = static_cast<LscpName *>(
            malloc(sizeof(LscpName) * entries.size()));
        memcpy(result->names, entries.data(),
            sizeof(LscpName) * entries.size());
    }
    return result;
}

extern "C" void lscp_sftp_free_names(LscpNames * names)
{
    if (names == NULL)
    {
        return;
    }
    for (int i = 0; i < names->count; i++)
    {
        free(names->names[i].filename);
        free(names->names[i].longname);
    }
    free(names->names);
    free(names);
}

extern "C" int lscp_sftp_mkdir(const char * path, int permissions)
{
    clear_error();
    WireAttrs attrs;
    if (permissions >= 0)
    {
        attrs.flags |= LSCP_ATTR_PERMISSIONS;
        attrs.permissions = static_cast<uint32_t>(permissions);
    }
    PacketBuilder body;
    body.str(path);
    write_attrs(body, attrs);
    return simple_op(SSH_FXP_MKDIR, body, "Creating the directory", path);
}

extern "C" int lscp_sftp_rmdir(const char * path)
{
    clear_error();
    PacketBuilder body;
    body.str(path);
    return simple_op(SSH_FXP_RMDIR, body, "Removing the directory", path);
}

extern "C" int lscp_sftp_remove(const char * path)
{
    clear_error();
    PacketBuilder body;
    body.str(path);
    return simple_op(SSH_FXP_REMOVE, body, "Removing", path);
}

extern "C" int lscp_sftp_rename(const char * from, const char * to)
{
    clear_error();
    PacketBuilder body;
    body.str(from);
    body.str(to);
    return simple_op(SSH_FXP_RENAME, body, "Moving", from);
}

extern "C" int lscp_sftp_set_permissions(const char * path, int permissions)
{
    clear_error();
    if (permissions < 0)
    {
        return 0;
    }
    WireAttrs attrs;
    attrs.flags |= LSCP_ATTR_PERMISSIONS;
    attrs.permissions = static_cast<uint32_t>(permissions);
    PacketBuilder body;
    body.str(path);
    write_attrs(body, attrs);
    return simple_op(SSH_FXP_SETSTAT, body,
        "Changing the permissions of", path);
}

extern "C" int lscp_sftp_set_times(const char * path, unsigned long atime,
    unsigned long mtime)
{
    clear_error();
    WireAttrs attrs;
    attrs.flags |= LSCP_ATTR_ACMODTIME;
    attrs.atime = static_cast<uint32_t>(atime);
    attrs.mtime = static_cast<uint32_t>(mtime);
    PacketBuilder body;
    body.str(path);
    write_attrs(body, attrs);
    return simple_op(SSH_FXP_SETSTAT, body, "Setting the times of", path);
}

extern "C" int lscp_sftp_symlink(const char * target, const char * linkPath)
{
    clear_error();
    /*
     * The SFTP draft and OpenSSH disagree on the argument order of
     * SSH_FXP_SYMLINK, and in practice servers (OpenSSH, paramiko, and
     * the one this client's test suite runs) expect the target first,
     * then the link path: that is the order the old client sent.
     */
    PacketBuilder body;
    body.str(target);
    body.str(linkPath);
    return simple_op(SSH_FXP_SYMLINK, body,
        "Creating the symbolic link", linkPath);
}

extern "C" int lscp_sftp_copy(const char * from, const char * to)
{
    clear_error();
    std::string readHandle;
    std::string writeHandle;
    if (open_handle(from, 1 /* SSH_FXF_READ */, NULL, readHandle,
            "Opening the source of the copy") != 0)
    {
        return -1;
    }
    if (open_handle(to, 2 /* SSH_FXF_WRITE */ | 8 /* CREAT */ | 16 /* TRUNC */,
            NULL, writeHandle, "Opening the target of the copy") != 0)
    {
        close_handle(readHandle);
        return -1;
    }

    PacketBuilder body;
    body.str("copy-data");
    body.str(readHandle);
    body.u64(0);
    body.u64(0); /* length 0: to the end of the source */
    body.str(writeHandle);
    body.u64(0);
    unsigned int responseType;
    std::vector<char> response;
    std::string statusMessage;
    const bool answered = request(SSH_FXP_EXTENDED, body, responseType,
        response, statusMessage);
    /* Closing the handles is a request of its own and would overwrite
     * g_last_status, so the copy's outcome is captured first. */
    const int copyStatus = g_last_status;
    const std::string copyMessage = statusMessage;
    close_handle(readHandle);
    close_handle(writeHandle);
    if (!answered)
    {
        return -1;
    }
    if (responseType != SSH_FXP_STATUS || copyStatus != SSH_FX_OK)
    {
        if (copyStatus == SSH_FX_OP_UNSUPPORTED)
        {
            set_error("The server does not implement the copy-data extension.");
            return -2;
        }
        set_error_path("Copying", from, copyMessage);
        return -1;
    }
    return 0;
}

extern "C" int lscp_sftp_checksum(const char * algorithm, const char * path,
    char * usedAlgorithm, size_t usedAlgorithmSize,
    char * hex, size_t hexSize)
{
    clear_error();
    if (usedAlgorithm != NULL && usedAlgorithmSize > 0)
    {
        usedAlgorithm[0] = '\0';
    }
    if (hex != NULL && hexSize > 0)
    {
        hex[0] = '\0';
    }

    PacketBuilder body;
    body.str("check-file-name");
    body.str(path);
    body.str(algorithm);
    body.u64(0);
    body.u64(0); /* length 0: the whole file */
    body.u32(0); /* block size 0: one block */
    unsigned int responseType;
    std::vector<char> response;
    std::string statusMessage;
    if (!request(SSH_FXP_EXTENDED, body, responseType, response, statusMessage))
    {
        return -1;
    }
    if (responseType == SSH_FXP_STATUS)
    {
        if (g_last_status == SSH_FX_OP_UNSUPPORTED)
        {
            set_error("The server does not implement the check-file-name "
                "extension.");
            return -2;
        }
        set_error_path("Calculating the checksum of", path, statusMessage);
        return -1;
    }
    if (responseType != SSH_FXP_EXTENDED_REPLY)
    {
        set_error_path("Calculating the checksum of", path, statusMessage);
        return -1;
    }
    /* EXTENDED_REPLY: algorithm name, block size (0: one block for the
     * whole range), then the digest as a length-prefixed string. */
    PacketReader reader(response.data(), response.size());
    const std::string used = reader.str();
    const uint32_t blockSize = reader.u32();
    const std::string digest = reader.str();
    if (!reader.ok || blockSize != 0 || digest.empty())
    {
        set_error("The server answered a checksum request with a "
            "malformed reply.");
        return -1;
    }
    const size_t digestLength = digest.size();
    if (usedAlgorithm != NULL && usedAlgorithmSize > 0)
    {
        if (used.size() + 1 > usedAlgorithmSize)
        {
            set_error("The server returned a checksum algorithm name that exceeds the caller's buffer.");
            return -1;
        }
        snprintf(usedAlgorithm, usedAlgorithmSize, "%s", used.c_str());
    }
    if (hex != NULL && hexSize > 0)
    {
        if (digestLength * 2 + 1 > hexSize)
        {
            set_error("The server returned a checksum digest that exceeds the caller's buffer.");
            return -1;
        }
        static const char digits[] = "0123456789abcdef";
        size_t out = 0;
        for (size_t i = 0; i < digestLength && out + 2 < hexSize; i++)
        {
            const unsigned char byte = static_cast<unsigned char>(digest[i]);
            hex[out++] = digits[byte >> 4];
            hex[out++] = digits[byte & 0x0f];
        }
        hex[out] = '\0';
    }
    return 0;
}

namespace {

unsigned long long local_file_size(FILE * file)
{
    struct stat st;
    if (fstat(fileno(file), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
    {
        return 0;
    }
    return static_cast<unsigned long long>(st.st_size);
}

/*
 * One download. 'remoteOffset' is the position in the remote file to read
 * from and 'localOffset' the position in the local file to write at; they
 * are the same for a resume and differ for an append. 'truncateLocal' says
 * whether an existing local file is overwritten.
 */
int get_transfer(const char * remotePath, const char * localPath,
    unsigned long long remoteOffset, unsigned long long localOffset,
    bool truncateLocal, unsigned long long * size,
    LscpProgressFn progress, void * progressCtx)
{
    clear_error();
    if (size != NULL)
    {
        *size = 0;
    }

    unsigned long long total = 0;
    LscpAttrs attrs;
    if (lscp_sftp_stat(remotePath, &attrs) == LSCP_SFTP_STAT_EXISTS &&
        (attrs.flags & LSCP_ATTR_SIZE))
    {
        total = attrs.size;
    }
    else
    {
        /* The open request below provides the authoritative failure. */
        clear_error();
    }

    std::string handle;
    if (open_handle(remotePath, 1 /* SSH_FXF_READ */, NULL, handle,
            "Opening the file") != 0)
    {
        return -1;
    }

    FILE * file;
    if (truncateLocal)
    {
        file = fopen(localPath, "wb");
    }
    else
    {
        /* Keep what is already there and write over or after it. Never fall
         * back to "ab" when localOffset > 0, because POSIX "a" ignores
         * fseeko() and appends every write at EOF; if the file is missing,
         * create it with "w+b" and seek to localOffset. */
        if (localOffset > 0)
        {
            file = fopen(localPath, "r+b");
            if (file == NULL && errno == ENOENT)
            {
                file = fopen(localPath, "w+b");
            }
            if (file != NULL &&
                fseeko(file, static_cast<off_t>(localOffset), SEEK_SET) != 0)
            {
                set_system_error("Seeking in the local file", localPath);
                fclose(file);
                close_handle(handle);
                return -1;
            }
        }
        else
        {
            file = fopen(localPath, "ab");
        }
    }
    if (file == NULL)
    {
        set_system_error("Creating the local file", localPath);
        close_handle(handle);
        return -1;
    }

    int result = 0;
    unsigned long long transferred = localOffset;
    uint64_t offset = remoteOffset;
    std::vector<char> buffer(TRANSFER_CHUNK);
    for (;;)
    {
        PacketBuilder body;
        body.str(handle);
        body.u64(offset);
        body.u32(TRANSFER_CHUNK);
        unsigned int responseType;
        std::vector<char> response;
        std::string statusMessage;
        if (!request(SSH_FXP_READ, body, responseType, response, statusMessage))
        {
            result = -1;
            break;
        }
        if (responseType == SSH_FXP_STATUS)
        {
            if (g_last_status == SSH_FX_EOF)
            {
                break;
            }
            set_error_path("Reading the file", remotePath, statusMessage);
            result = -1;
            break;
        }
        if (responseType != SSH_FXP_DATA)
        {
            set_error_path("Reading the file", remotePath, statusMessage);
            result = -1;
            break;
        }
        PacketReader reader(response.data(), response.size());
        const std::string data = reader.str();
        if (!reader.ok)
        {
            set_error("The server answered a read with malformed data.");
            result = -1;
            break;
        }
        if (data.empty())
        {
            break;
        }
        if (fwrite(data.data(), 1, data.size(), file) != data.size())
        {
            set_system_error("Writing the local file", localPath);
            result = -1;
            break;
        }
        offset += data.size();
        transferred += data.size();
        if (progress != NULL)
        {
            progress(transferred, total, progressCtx);
        }
    }

    errno = 0;
    if (fclose(file) != 0 && result == 0)
    {
        set_system_error("Closing the local file", localPath);
        result = -1;
    }
    if (close_handle(handle) != 0 && result == 0)
    {
        set_error_path("Closing the file", remotePath, std::string());
        result = -1;
    }
    if (result != 0)
    {
        return -1;
    }
    if (size != NULL)
    {
        *size = transferred;
    }
    return 0;
}

/* Size of a local path, or 0 when it does not exist. */
unsigned long long path_size(const char * path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
    {
        return 0;
    }
    return static_cast<unsigned long long>(st.st_size);
}

/*
 * One upload, with the local read position, the remote write position and
 * whether the remote file is truncated kept apart so that an append can
 * start at the end of the remote file while reading the local one from its
 * beginning.
 */
int put_transfer(const char * localPath, const char * remotePath,
    int permissions, unsigned long long localOffset,
    unsigned long long remoteOffset, bool truncateRemote,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx)
{
    clear_error();
    if (size != NULL)
    {
        *size = 0;
    }

    FILE * file = fopen(localPath, "rb");
    if (file == NULL)
    {
        set_system_error("Opening the local file", localPath);
        return -1;
    }
    const unsigned long long total = local_file_size(file);
    if (localOffset > 0 &&
        fseeko(file, static_cast<off_t>(localOffset), SEEK_SET) != 0)
    {
        set_system_error("Seeking in the local file", localPath);
        fclose(file);
        return -1;
    }

    WireAttrs attrs;
    if (permissions >= 0)
    {
        attrs.flags |= LSCP_ATTR_PERMISSIONS;
        attrs.permissions = static_cast<uint32_t>(permissions);
    }
    uint32_t access = 2 /* SSH_FXF_WRITE */ | 8 /* SSH_FXF_CREAT */;
    if (truncateRemote)
    {
        access |= 16 /* SSH_FXF_TRUNC */;
    }
    std::string handle;
    if (open_handle(remotePath, access,
            permissions >= 0 ? &attrs : NULL, handle,
            "Creating the file") != 0)
    {
        fclose(file);
        return -1;
    }

    int result = 0;
    unsigned long long transferred = remoteOffset;
    uint64_t offset = remoteOffset;
    std::vector<char> buffer(TRANSFER_CHUNK);
    for (;;)
    {
        const size_t read = fread(buffer.data(), 1, buffer.size(), file);
        if (read == 0)
        {
            if (ferror(file))
            {
                set_system_error("Reading the local file", localPath);
                result = -1;
            }
            break;
        }
        PacketBuilder body;
        body.str(handle);
        body.u64(offset);
        body.str(buffer.data(), read);
        unsigned int responseType;
        std::vector<char> response;
        std::string statusMessage;
        if (!request(SSH_FXP_WRITE, body, responseType, response,
                statusMessage))
        {
            result = -1;
            break;
        }
        if (responseType != SSH_FXP_STATUS || g_last_status != SSH_FX_OK)
        {
            set_error_path("Writing the file", remotePath, statusMessage);
            result = -1;
            break;
        }
        offset += read;
        transferred += read;
        if (progress != NULL)
        {
            progress(transferred, total, progressCtx);
        }
    }

    errno = 0;
    if (fclose(file) != 0 && result == 0)
    {
        set_system_error("Closing the local file", localPath);
        result = -1;
    }
    if (close_handle(handle) != 0 && result == 0)
    {
        set_error_path("Closing the file", remotePath, std::string());
        result = -1;
    }
    if (result != 0)
    {
        return -1;
    }
    if (size != NULL)
    {
        *size = transferred;
    }
    return 0;
}

} // namespace

extern "C" int lscp_sftp_get(const char * remotePath, const char * localPath,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx)
{
    return get_transfer(remotePath, localPath, 0, 0, true, size, progress,
        progressCtx);
}

extern "C" int lscp_sftp_get_resume(const char * remotePath,
    const char * localPath, unsigned long long resumeOffset,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx)
{
    return get_transfer(remotePath, localPath, resumeOffset, resumeOffset,
        resumeOffset == 0, size, progress, progressCtx);
}

extern "C" int lscp_sftp_get_append(const char * remotePath,
    const char * localPath, unsigned long long * size,
    LscpProgressFn progress, void * progressCtx)
{
    return get_transfer(remotePath, localPath, 0, path_size(localPath), false,
        size, progress, progressCtx);
}

extern "C" int lscp_sftp_put(const char * localPath, const char * remotePath,
    int permissions, unsigned long long * size, LscpProgressFn progress,
    void * progressCtx)
{
    return put_transfer(localPath, remotePath, permissions, 0, 0, true, size,
        progress, progressCtx);
}

extern "C" int lscp_sftp_put_resume(const char * localPath,
    const char * remotePath, int permissions,
    unsigned long long resumeOffset, unsigned long long * size,
    LscpProgressFn progress, void * progressCtx)
{
    return put_transfer(localPath, remotePath, permissions, resumeOffset,
        resumeOffset, resumeOffset == 0, size, progress, progressCtx);
}

/*
 * Appends the local file to the remote one. The remote size comes from the
 * server, because an upload must continue where the remote file ends; a
 * missing destination simply starts at zero.
 */
extern "C" int lscp_sftp_put_append(const char * localPath,
    const char * remotePath, int permissions, unsigned long long * size,
    LscpProgressFn progress, void * progressCtx)
{
    LscpAttrs attrs;
    unsigned long long remoteOffset = 0;
    if (lscp_sftp_stat(remotePath, &attrs) == LSCP_SFTP_STAT_EXISTS &&
        (attrs.flags & LSCP_ATTR_SIZE) != 0)
    {
        remoteOffset = attrs.size;
    }
    return put_transfer(localPath, remotePath, permissions, 0, remoteOffset,
        false, size, progress, progressCtx);
}
