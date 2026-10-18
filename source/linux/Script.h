/*
 * Script: the command interpreter of the POSIX front end, following the
 * command set of the WinSCP console client so that existing scripts keep
 * working.
 */

#ifndef LINSCP_SCRIPT_H
#define LINSCP_SCRIPT_H

#include <string>
#include <utility>
#include <vector>

#include "Editor.h"
#include "LocalFs.h"
#include "Session.h"
#include "SessionStore.h"
#include "SftpClient.h"
#include "SyncPlanner.h"
#include "TextMode.h"
#include "TransferPresets.h"

namespace linscp {

/*
 * Upstream's TResumeSupport, as the persistent 'option resume' setting:
 * 'Automatic' is upstream's default rsSmart (binary files from a size
 * threshold on resume), 'On' is rsOn and 'Off' rsOff. It decides what a
 * transfer does when no '-resumesupport=' switch overrides it, and with
 * it whether the transfer stages its data in the '.filepart' name that
 * upstream uses before moving the completed file into place.
 */
enum class ResumeMode { Automatic, On, Off };

/*
 * One 'name=value' pair of upstream's '-rawsettings' switch ('open' and
 * 'savesession'). They are collected before they are applied so that the
 * settings a stored session already carries are the base they change.
 */
typedef std::pair<std::string, std::string> RawSetting;

/*
 * The switches of an 'open' command. They apply to a stored site as well
 * as to a URL - upstream parses both through the same code, so
 * 'open <site> -password=...' authenticates the stored site with that
 * password - and each one is only applied when it was actually given.
 */
struct OpenSwitches
{
    bool hostKeyGiven;
    bool passwordGiven;
    bool userNameGiven;
    bool privateKeyGiven;
    bool passphraseGiven;
    std::string hostKey;
    std::string password;
    std::string userName;
    std::string privateKeyFile;
    std::string passphrase;
    std::vector<RawSetting> rawSettings;

    OpenSwitches() : hostKeyGiven(false), passwordGiven(false),
        userNameGiven(false), privateKeyGiven(false),
        passphraseGiven(false) {}
};

struct TransferFlags
{
    /* 'get -delete' / 'put -delete': remove the source after a transfer. */
    bool deleteSource;
    /* 'synchronize -delete': remove target entries that the source does
     * not have. It never removes the source, where the user's data
     * lives. */
    bool deleteObsolete;
    bool newerOnly;
    bool preserveTime;
    bool recursive;
    bool resume;
    /* The effective file mask ('-filemask=' or 'option include/exclude'). */
    FileMask mask;
    /* binary, ASCII or automatic line-ending conversion. */
    TransferMode transferMode;
    /* -permissions= for uploads, -1 to leave the server's default. */
    int permissions;
    /* -filemask= was given for this command. */
    bool maskGiven;
    /*
     * -resumesupport= : how resuming is decided. 'Smart' resumes only when
     * the file to transfer is at least 'resumeThreshold' bytes big, like the
     * upstream transfer setting of the same name. Unset leaves the decision
     * to '-resume' and 'option resume'.
     */
    enum ResumeSupport
    {
        ResumeUnset,
        ResumeOff,
        ResumeOn,
        ResumeSmart
    };
    ResumeSupport resumeSupport;
    unsigned long long resumeThreshold;
    /* '-speed=' in kibibytes per second; 0 transfers as fast as it can. */
    unsigned speedKBytesPerSecond;
    /* '-append': add to the destination instead of replacing it. */
    bool append;
    /* '-preservetime=all': also give the transferred directories the
     * timestamps of their source, not just the files. */
    bool preserveTimeDirs;
    /*
     * Settings a switch of this command pinned (bit 0 transfer, 1
     * preservetime, 2 neweronly, 3 resume, 4 permissions). A mask
     * preset may override the session's values for one file but never
     * a setting the command line stated itself.
     */
    unsigned explicitSettings;

    TransferFlags() : deleteSource(false), deleteObsolete(false),
        newerOnly(false), preserveTime(false), recursive(true),
        resume(false), transferMode(TransferMode::Binary), permissions(-1),
        maskGiven(false), resumeSupport(ResumeUnset), resumeThreshold(0),
        speedKBytesPerSecond(0), append(false), preserveTimeDirs(false),
        explicitSettings(0) {}
};

class Script
{
public:
    Script();

    /* Options that 'open' fills in when the URL does not say otherwise. */
    void SetDefaults(const SessionOptions & options) { mDefaults = options; }

    /*
     * The script parameters of this run, substituted for %1% .. %9% in every
     * command line before it is parsed, as the upstream console does with
     * '/parameter a b c'. The expansion is off in '-server' mode, where the
     * commands come from a program that has no parameters to pass and where a
     * file name may legitimately contain a percent sign.
     */
    void SetScriptParameters(const std::vector<std::string> & parameters)
        { mParameters = parameters; }

    /* Runs a whole script file ('-' for standard input). */
    int RunFile(const std::string & path);
    /* Runs the command(s) given on the command line, ';' separated. */
    int RunCommand(const std::string & line, bool literal = false);
    /* Reads commands from the terminal until 'exit'. */
    int RunInteractive(const std::string & initialUrl);
    /* Reads one command per line from stdin and prints the outcome of
     * each one after a 'LSCP-RESULT' marker. This is how the graphical
     * client keeps a session open between two operations instead of
     * connecting again for every listing. */
    int RunServer();
    /* Executes one command line; returns false when the client must stop. */
    bool ExecuteLine(const std::string & line);

    int ErrorCount() const { return mErrors; }
    bool ExitRequested() const { return mExit; }
    /* True when the command that ran last reported an error. Used by the
     * server loop, which reports the outcome of every command. */
    bool LastCommandFailed() const { return mLastCommandFailed; }
    /* The stored sessions (site manager) of this client. */
    SessionStore & Sessions() { return mSessions; }
    /* The remote file listing as the synchronization planner needs it. */
    bool ListRemoteEntries(const std::string & path, std::vector<SyncEntry> & entries,
        std::string & error);
    /* One remote file's checksum as lowercase hexadecimal, computed by the
     * server when it can and from a downloaded copy otherwise. 'note'
     * receives what the caller may tell the user about which of the two it
     * was. The 'checksum' command and the synchronization planner's
     * '-criteria=checksum' both go through it. */
    bool RemoteChecksumFile(const std::string & path,
        const std::string & algorithm, std::string & hex, std::string & note,
        std::string & error);
    /* The three remote operations the editor needs, so that Editor.cpp
     * does not have to know anything about the session. */
    int StatForEdit(const std::string & path, LscpAttrs & attrs, std::string & error);
    int DownloadForEdit(const std::string & remote, const std::string & local,
        bool preserveTime, std::string & error);
    int UploadForEdit(const std::string & local, const std::string & remote,
        bool preserveTime, std::string & error);


private:
    Script(const Script &);
    Script & operator=(const Script &);

    bool ExecuteCommand(const std::string & line);
    /*
     * Expands the script parameters, %TIMESTAMP% and the environment in one
     * command line. Reports the problem and counts an error when a placeholder
     * is malformed, because keeping it would move files to a wrong path.
     */
    bool ExpandParameters(const std::string & line, std::string & expanded);
    /*
     * Turns an abbreviated name - a command, an option name or an option
     * value - into the full one, the way the upstream command table does: an
     * unambiguous prefix is enough, a prefix that fits several names is
     * refused. Returns false once that ambiguity is reported; on true,
     * 'resolved' holds the full name or is empty when nothing matched and the
     * caller should produce its own message.
     */
    bool ResolveAbbreviation(const std::vector<std::string> & names,
        const std::string & typed, const std::string & what,
        std::string & resolved);
    /*
     * Reads the switches of 'get' and 'put' into 'flags' and the file names
     * into 'paths'. Everything it does not understand is reported before a
     * connection is made or a file is touched, so that a switch is never
     * silently ignored. 'uploads' selects the switches of the upload
     * direction ('-permissions=').
     */
    /* The active preset's settings into fresh flags, before switches. */
    bool ApplySessionPreset(TransferFlags & flags, std::string & error);
    /* The first mask preset accepting this file, into its flags. */
    void ApplyMaskPreset(const std::string & fileName, TransferFlags & flags);
    bool ParseTransferSwitches(const std::string & command, bool uploads,
        const std::vector<std::string> & args, TransferFlags & flags,
        std::vector<std::string> & paths);
    /* Whether one file of this size is resumed under 'flags'. */
    bool Resumes(const TransferFlags & flags, unsigned long long size) const;

    /*
     * One file's journey through the '.filepart' staging name that upstream
     * uses for resume-capable transfers: bytes are written to '<final>'
     * while they are incomplete, and the finished file is moved onto
     * '<final>' only once it is complete, so an interrupted transfer never
     * leaves a truncated file where a whole one belongs.
     */
    struct TransferStage
    {
        /* The transfer uses the staging name at all. */
        bool staged;
        /* Direction: upload writes a remote staging file, download a
         * local one. */
        bool upload;
        /* A usable '<final>.filepart' existed: continue at 'resumeOffset'
         * instead of transferring from byte zero. */
        bool continuing;
        /* The staging file already holds every byte: skip the transfer
         * and only move the file into place. */
        bool complete;
        /* The staging file exists but cannot be continued (it is bigger
         * than the source, or the source size is unknown): it is removed
         * before the transfer starts. */
        bool stale;
        unsigned long long resumeOffset;
        std::string finalPath;
        std::string partPath;
        TransferStage() : staged(false), upload(false), continuing(false),
            complete(false), stale(false), resumeOffset(0) {}
    };

    /*
     * Resolves staging for one transfer. 'eligible' is the caller's
     * decision that this transfer may resume at all (Resumes() and no
     * '-append'); 'upload' selects the direction; 'totalSize' is the size
     * of the source, 0 when it is unknown. Read-only: the existing staging
     * file is inspected and a continuation is announced, but nothing is
     * written or removed - that happens in PrepareStage, after the caller
     * has confirmed overwriting the destination.
     */
    /*
     * Whether the transport of the open session can continue a partial
     * file: the native SFTP engine and the curl protocols with a byte
     * range can, and SCP cannot - its rcp protocol has no offset, so a
     * staging file that is already there is discarded and the transfer
     * starts again instead of being spliced.
     */
    bool TransportContinues() const;

    bool ResolveStage(bool eligible, bool upload,
        const std::string & finalPath, unsigned long long totalSize,
        TransferStage & stage, std::string & error);
    /* Removes a staging file that cannot be continued; clears 'stale'
     * once nothing is in the way. No-op otherwise. */
    bool PrepareStage(TransferStage & stage, std::string & error);
    /*
     * Moves a completed staging file onto its final path. Locally this is
     * the POSIX rename, which replaces an existing file in one step;
     * remotely the destination is removed first, because not every
     * protocol's rename replaces. On failure the complete data stays in
     * the staging file and 'error' says so.
     */
    bool FinishStage(const TransferStage & stage, std::string & error);

    /* Reports a switch 'get' or 'put' cannot honour and counts an error;
     * always returns false, so that a parser can 'return SwitchError(...)'. */
    bool SwitchError(const std::string & command, const std::string & hint);
    bool ListLocal(const std::vector<std::string> & args);
    bool OpenSite(const std::vector<std::string> & args);
    void CloseSite(const std::vector<std::string> & args);
    bool ChangeRemoteDirectory(const std::vector<std::string> & args);
    void PrintRemoteDirectory();
    bool ListRemote(const std::vector<std::string> & args);
    void NoMatch(const std::string & mask, const std::string & error);
    bool ChangeLocalDirectory(const std::vector<std::string> & args);
    void PrintLocalDirectory();
    bool GetFiles(const std::vector<std::string> & args);
    bool PutFiles(const std::vector<std::string> & args);
    bool SynchronizeDirectories(const std::vector<std::string> & args);
    /* Reads the switches of 'synchronize' and 'keepuptodate'. Returns
     * false with 'error' set for anything it does not support, so that
     * an unsupported switch is never silently ignored. */
    bool ParseSyncArguments(const std::vector<std::string> & args,
        const std::string & command, SyncOptions & options,
        std::vector<std::string> & dirs, bool & preview, int & interval,
        int & count, bool & continueOnError, bool modeOptional,
        std::string & error);
    /* Compares the two trees and fills 'plan'. */
    bool BuildSynchronizationPlan(SyncOptions & options,
        const std::string & localDir, const std::string & remoteDir,
        SyncPlan & plan, SyncState * state, std::string & error);
    /* Applies a plan. Nothing is removed unless the plan was confirmed;
     * a plan with conflicts is applied only as far as the transfers. */
    bool ExecuteSynchronizationPlan(SyncPlan & plan, const SyncOptions & options,
        bool allowDelete, unsigned long long & bytesTransferred);
    /* Prints a plan in a fixed, tab-separated format that a script or
     * the graphical client can read back. */
    void PrintSynchronizationPlan(const SyncPlan & plan) const;
    bool KeepUpToDate(const std::vector<std::string> & args);
    bool EditRemoteFile(const std::vector<std::string> & args);
    bool SessionCommand(const std::vector<std::string> & args);
    bool StoredSessionsCommand(const std::vector<std::string> & args);
    bool SaveStoredSession(const std::vector<std::string> & args);
    bool SavePresetCommand(const std::vector<std::string> & args);
    bool RemovePresetCommand(const std::vector<std::string> & args);
    bool ListPresetsCommand(const std::vector<std::string> & args);
    bool RemoveStoredSessionEntry(const std::vector<std::string> & args);
    /* Opens a stored session by name; false when there is no such
     * session, in which case the caller falls back to a URL. The
     * switches of the 'open' command are applied on top of the settings
     * the site was stored with, as upstream applies them. */
    bool OpenStoredSite(const std::string & name,
        const OpenSwitches & switches = OpenSwitches());
    bool RemoveRemote(const std::vector<std::string> & args);
    bool RemoveRemoteDirectory(const std::vector<std::string> & args);
    bool MakeRemoteDirectory(const std::vector<std::string> & args);
    bool MoveRemote(const std::vector<std::string> & args);
    /* 'cp': remote copy, server-side when the protocol can, streamed
     * through a local temporary file otherwise. */
    bool CopyRemote(const std::vector<std::string> & args);
    /* One file or tree to one exact destination. */
    bool CopyRemoteTree(const std::string & from, const std::string & to);
    bool CopyRemoteOneFile(const std::string & from, const std::string & to);
    /* 'ln'/'symlink': target first, like ln(1) and WinSCP. */
    bool LinkRemote(const std::vector<std::string> & args, const char * name);
    /* 'checksum <algorithm> <file>': server-side when the protocol can,
     * otherwise computed while downloading. */
    bool ChecksumRemote(const std::vector<std::string> & args);
    /* WebDAV locks and dead properties (LinSCP extensions). */
    bool LockRemote(const std::vector<std::string> & args);
    bool UnlockRemote(const std::vector<std::string> & args);
    bool DavPropertyCommand(const std::vector<std::string> & args);
    /* WebDAV ETag preconditions: 'etag FILE -match=ETAG|-nomatch=ETAG|-clear'
     * sets or clears If-Match/If-None-Match for subsequent writes. */
    bool EtagCommand(const std::vector<std::string> & args);
    /* 'call'/'!': runs one command on the server through a second SSH
     * connection that executes it instead of the SFTP subsystem. */
    bool CallRemote(const std::vector<std::string> & args, const char * name);
    /* 'copyid': installs the public half of the configured private key
     * in the server's authorized_keys. */
    bool CopyPublicKey(const std::vector<std::string> & args);
    bool ChangeRemotePermissions(const std::vector<std::string> & args);
    /* Applies an octal or symbolic mode to one remote path, and to
     * everything below it when 'recursive' asks for that. Symbolic links
     * are skipped, so that a recursive run cannot leave the directory tree. */
    bool ApplyRemotePermissions(const std::string & path, const std::string & mode,
        bool recursive, unsigned long long & changed);
    bool StatRemote(const std::vector<std::string> & args);
    bool AttrRemote(const std::vector<std::string> & args);
    bool SetOption(const std::vector<std::string> & args);
    void OpenTerminal(const std::vector<std::string> & args);
    void PrintHelp(const std::vector<std::string> & args);
    /* Help text of one command, or NULL. */
    static std::string CommandHelp(const std::string & command);
    void PrintStatus();

    bool DownloadDirectoryRecursive(const std::string & remoteDir,
        const std::string & localDir, const TransferFlags & flags,
        unsigned long long & bytesTransferred,
        const std::string & relPrefix = std::string());
    bool UploadDirectoryRecursive(const std::string & localDir,
        const std::string & remoteDir, const TransferFlags & flags,
        unsigned long long & bytesTransferred,
        const std::string & relPrefix = std::string());
    bool CreateRemoteDirectoryRecursive(const std::string & path,
        std::string & error);

    /* Records the timestamps and the size of a file that is (or has just
     * been brought) in sync, so that the next pass can tell a change on
     * one side from a change on both. */
    void RecordSyncState(SyncState * state, const std::string & relative,
        const std::string & localPath, const std::string & remotePath);

    /* Removes one entry, a directory tree included. Used by 'synchronize
     * -delete' for the entries the other side does not have. */
    bool RemoveLocalItemRecursive(const std::string & path);
    bool RemoveRemoteItemRecursive(const std::string & path);
    /* Asks before removing one obsolete entry; true when it may go. */
    bool ConfirmObsolete(const std::string & side, const std::string & path,
        bool isDirectory);

    bool RequireConnection();
    /* True when 'batch on/abort' says a multi-file command must stop at
     * the first failing file instead of continuing with the rest. */
    bool AbortAfterFileError() const;
    /* Fills flags.mask from -filemask= or 'option include/exclude'. */
    void ResolveTransferMask(TransferFlags & flags) const;
    /* Expands a remote argument (possibly a mask) into full paths. */
    bool ExpandRemote(const std::string & pattern, std::vector<std::string> & paths,
        std::string & error);
    void PrintRemoteEntry(const std::string & name, const LscpName & entry,
        bool longFormat = true);

    bool RemoteListDir(const std::string & path, LscpNames *& names, std::string & error);
    void RemoteFreeNames(LscpNames * names);
    int RemoteStat(const std::string & path, LscpAttrs * attrs, std::string & error);
    /* 'append' adds the source to the end of an existing destination
     * instead of replacing it; only the native SFTP transport can position
     * a write, so it is refused elsewhere. */
    int RemoteGet(const std::string & remote, const std::string & local,
        unsigned long long resumeOffset, bool preserveTime, unsigned long long * size,
        LscpProgressFn progress, void * ctx, std::string & error,
        bool append = false);
    int RemotePut(const std::string & local, const std::string & remote,
        int permissions, unsigned long long resumeOffset, bool preserveTime,
        unsigned long long * size, LscpProgressFn progress, void * ctx,
        std::string & error, bool append = false);
    /* Gives a remote path the timestamps of its local source (the
     * directory half of 'put -preservetime=all'). */
    int RemoteSetTimes(const std::string & path, unsigned long atime,
        unsigned long mtime, std::string & error);
    /* The same transfers with ASCII line-ending conversion applied
     * around the binary transfer when the mode asks for it.
     * 'sourceSize' is the size of the file being transferred, used for
     * the '.filepart' staging decision; 0 when it is unknown. */
    int RemoteGetMode(const std::string & remote, const std::string & local,
        TransferMode mode, unsigned long long sourceSize,
        unsigned long long * size, std::string & error);
    int RemotePutMode(const std::string & local, const std::string & remote,
        TransferMode mode, unsigned long long sourceSize,
        unsigned long long * size, std::string & error);
    int RemoteRemove(const std::string & path, std::string & error);
    int RemoteRemoveDir(const std::string & path, std::string & error);
    int RemoteMakeDir(const std::string & path, int permissions, std::string & error);
    int RemoteRename(const std::string & from, const std::string & to, std::string & error);
    int RemoteSetPermissions(const std::string & path, int permissions, std::string & error);
    /* Remote copy through a local temporary file; the fallback 'cp' path
     * and the building block of the checksum fallback. */
    int RemoteStreamCopy(const std::string & from, const std::string & to,
        std::string & error);
    int RemoteSymlink(const std::string & target, const std::string & linkPath,
        std::string & error);


    SessionOptions mDefaults;
    /* Script parameters of this run, for the %1% .. %9% expansion. */
    std::vector<std::string> mParameters;
    Session mSession;
    SessionStore mSessions;
    std::string mRemoteDirectory;
    /* The directory the server starts the session in; 'cd' with no
     * argument goes there. */
    std::string mHomeDirectory;
    /* Name of the stored session that was opened, so that 'savesession'
     * keeps it and 'open' can report it. */
    std::string mStoredSessionName;
    enum class BatchMode { Off, On, Abort, Continue };
    BatchMode mBatchMode;
    bool mBatchConfigured;
    bool mConfirm;
    /* 'option resume': upstream's persistent resume setting. */
    ResumeMode mResumeMode;
    bool mExit;
    int mErrors;
    bool mLastCommandFailed;
    /* 'option editor': the program 'edit' runs, or empty to use the
     * environment. */
    std::string mEditor;
    unsigned long long mEditMaxSize;
    /* 'option transfer' / 'ascii' / 'binary' / '-transfer='. */
    /*
     * The active transfer preset: a name chosen with 'option preset',
     * stored with a site ('savesession -preset=') or, when no name is
     * set, the first preset whose host/user/directory rule matches the
     * connection. The store reloads from transfer-presets.ini whenever
     * a transfer resolves it, so an edit to the file takes effect.
     */
    TransferPresetStore mPresets;
    std::string mActivePresetName;
    /* Set by 'option preset off': no preset at all for this session,
     * not even one whose host/user/directory rule matches. */
    bool mPresetOff = false;
    TransferMode mTransferMode;
    /* 'option include' / 'option exclude' (one WinSCP mask: setting one
     * half replaces the other, like upstream). */
    FileMask mOptionMask;
    bool mOptionMaskUsed;
    /* 'option failonnomatch': a mask that selects nothing is an error. */
    bool mFailOnNoMatch;
    /* 'option echo': print every command before running it. */
    bool mEchoCommands;
    /* 'option reconnecttime': reopen a dropped session, in seconds. */
    int mReconnectSeconds;
    /* 'option synchdelete': the default of 'synchronize -delete'. */
    bool mSyncDeleteDefault;
    /* '-speed=' of the command being run, in kibibytes per second. */
    unsigned mSpeedLimit;
    /* True while the -server loop of the graphical client runs: its
     * echo must stay off so the protocol stays readable. */
    bool mServerLoop;
};

} // namespace linscp

#endif /* LINSCP_SCRIPT_H */
