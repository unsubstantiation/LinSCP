# Backup portability and recovery boundaries

Full backups and encrypted key/session exports are different formats. Keep the
backup password separately and test a restore before relying on a backup.

Full backups include the stored configuration, vault SSH keys and TLS blobs,
and rewrap vault material using the destination vault. They refuse export when
saved sessions refer to external SSH keys, public keys, certificate files or CA
directories, or file-based/invalid public-key pins, instead of claiming those
files are portable. The key/session exporter can embed supported external key
and TLS files and convert file-based pins to hashes; it explicitly refuses
unsupported or unreadable fields and size-limit violations. Local working
folders, commands, and other device-specific settings are not guaranteed to exist
or behave identically on another device. An old full backup created before this
check can still contain external paths and requires manual repair after restore.

The key/session import merges selected sessions. A conflicting shared transfer
preset or SSH host key is refused, including when replacing same-named sessions:
replacing a session does not authorize changing shared trust or transfer settings
used by other sessions. Resolve conflicts deliberately before retrying.

Full restore uses an encrypted undo journal and recovery gate; interrupted or
damaged journal recovery must be resolved before configuration is exposed. The
key/session merge is **not** a durable multi-file transaction: interruption or a
write error can leave staged keys or a partially applied merge. In particular,
retain the original backup and inspect sessions, host keys and presets after a
failed import. Created keys are not removed after a session write is attempted,
since the write can report an error after publication. This is not a guarantee
of atomic selective import or cleanup of orphaned keys.

Automated Linux/Windows tests exercise backup validation and merge behavior; the
existing Android emulator test exercises full restore and real SFTP public-key
authentication after rewrapping and restart. These are not proof of physical
device behavior, inter-OS authentication against every SSH server, or every
possible filesystem failure.
