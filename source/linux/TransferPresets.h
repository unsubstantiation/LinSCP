/*
 * TransferPresets: named sets of transfer settings with an optional
 * applicability rule - the shape of upstream's TCopyParamList, which
 * WinSCP's GUI edits in its "transfer settings preset" dialog and
 * applies by rule (host name, user name, remote directory, local
 * directory and a file mask), with the settings themselves being the
 * fields of its TCopyParamType.
 *
 * This client keeps the presets in an INI file next to sessions.ini,
 * one section per preset:
 *
 *   [web-text]
 *   transfer = ascii
 *   preservetime = on
 *   mask = *.txt|*.html
 *   host = example.com
 *   user = alice
 *   remotedir = /srv/www
 *   localdir = /srv/www
 *
 * The settings use this client's switch vocabulary (transfer,
 * preservetime, neweronly, speed, resumesupport, permissions) because
 * that is what a script reads; the numbers upstream writes with its
 * own names are accepted from '-rawtransfersettings', which speaks
 * upstream's key names directly.
 *
 * A preset applies in three places: 'option preset <name>' selects one
 * for the session, a stored site can carry one ('savesession
 * -preset=<name>'), and a preset whose host/user/directory rule matches
 * the connection applies on its own. A preset with a mask rule then
 * overrides its settings per transferred file - that is how
 * '*.txt = ascii' becomes true for exactly those files.
 */

#ifndef LINSCP_TRANSFERPRESETS_H
#define LINSCP_TRANSFERPRESETS_H

#include <string>
#include <vector>

namespace linscp {

struct TransferFlags;
enum class TransferMode;

struct TransferPreset
{
    std::string name;

    /* Settings; negative/unset means the preset does not say. The
     * integers for transfer and resumesupport are upstream's own
     * numbering (TransferMode: 0 binary, 1 ascii, 2 automatic;
     * ResumeSupport: 0 on, 1 smart, 2 off). */
    int transferMode;
    int preserveTime;
    int preserveTimeDirs;
    int newerOnly;
    /* Octal mode for uploads, -3 unset, -1 explicit off (leave server
     * default), -2 means "the file's own permissions" for downloads. */
    int permissions;
    int resumeSupport;
    /* Bytes for the threshold, kibibytes per second for the limit. */
    long long resumeThreshold;
    long long speedLimit;

    /* Rule; empty = any. 'mask' is matched against each transferred
     * file name, the other fields against the connection. */
    std::string host;
    std::string userName;
    std::string remoteDirectory;
    std::string localDirectory;
    std::string mask;

    TransferPreset()
        : transferMode(-1), preserveTime(-1), preserveTimeDirs(-1),
          newerOnly(-1), permissions(-3), resumeSupport(-1),
          resumeThreshold(-1), speedLimit(-1)
    {
    }

    /* True when at least one of host/user/remote/local is set: such a
     * preset is a session rule rather than a per-file mask rule. */
    bool HasSessionRule() const;
    bool HasMaskRule() const { return !mask.empty(); }

    /* Applies the settings this preset states to transfer flags. */
    void ApplyTo(TransferFlags & flags) const;

    /* One line for the 'presets' listing: settings, then the rule. */
    std::string Describe() const;
};

class TransferPresetStore
{
public:
    /* The file is read on construction; a missing or unreadable file
     * is not an error, it simply leaves the store empty. */
    TransferPresetStore();
    explicit TransferPresetStore(const std::string & path);

    /* Configuration directory + "transfer-presets.ini". */
    static std::string DefaultPath();
    const std::string & Path() const { return mPath; }

    bool Load(std::string & error);
    bool Save(std::string & error) const;

    const std::vector<TransferPreset> & Presets() const { return mPresets; }
    bool Empty() const { return mPresets.empty(); }

    /* Case-insensitive when there is no exact match, like sessions. */
    const TransferPreset * Find(const std::string & name) const;

    bool AddOrUpdate(const TransferPreset & preset, std::string & error);
    bool Remove(const std::string & name, std::string & error);

    /* The first preset whose session rule (host, user, directories -
     * never the mask) matches; the empty connection fields match any
     * preset value, so a preset may constrain only some of them. */
    const TransferPreset * MatchSession(const std::string & host,
        const std::string & user, const std::string & remoteDirectory,
        const std::string & localDirectory) const;

    /* The first preset with a mask rule accepting the file name. */
    const TransferPreset * MatchMask(const std::string & fileName) const;

    /* Reads one 'key = value' line of a preset. The keys are this
     * client's switch names: transfer, preservetime, neweronly, speed,
     * resumesupport, permissions, host, user, remotedir, localdir,
     * mask. */
    static bool ParseSetting(const std::string & key,
        const std::string & value, TransferPreset & preset,
        std::string & error);

    /* Validates a name the way session names are validated. */
    static bool IsValidName(const std::string & name);

private:
    TransferPresetStore(const TransferPresetStore &);
    TransferPresetStore & operator=(const TransferPresetStore &);

    std::vector<TransferPreset> mPresets;
    std::string mPath;
};

} // namespace linscp

#endif /* LINSCP_TRANSFERPRESETS_H */
