# Local credential vault

LinSCP's Commander UI now requires a separate local-vault password at each
launch. The password is not saved. A random 256-bit data-encryption key remains
in process memory only after setup/unlock; `sessions.key` stores that key
wrapped with AES-256-GCM. The wrapping key is derived from the password with
Argon2id (64 MiB, three iterations, one lane) and a random salt. Existing
legacy `sessions.key` files are upgraded in place on first setup without
changing the key used to decrypt existing saved-session passwords.

Saved session passwords continue to use LinSCP's encrypted `sessions.ini`
format with the random data key. The Site Manager has two separate entries,
both stored encrypted under that key when the "store the passwords" option is
ticked: `User Password`, the login password for the server (terminal and
permissions access), and `Key Password`, the passphrase that decrypts an
encrypted OpenSSH private key. The option is ticked by default for new SSH
sessions; uncheck it to keep the passwords only for the current connection.
An empty field with the option ticked keeps the secret already stored for the
site, so re-saving a session does not wipe its saved passwords; unchecking
the box on save removes them. SSH private-key files selected with
the browse button are imported into the vault and encrypted with AES-256-GCM
under that same in-memory key. Their session values are opaque `vaultkey://`
references; existing vault keys can be selected with the key-picker button.
LinSCP does not modify the source key file. For an SSH connection it creates a
private, short-lived temporary key file and removes it when the connection
attempt returns. Explicitly locking the
vault disconnects sessions and drops the in-memory key. Process exit also drops
the key.

This does not encrypt original key files selected from elsewhere on the
computer; LinSCP does not overwrite or delete user-owned source files. It
protects LinSCP's own saved copy. Public keys are not secret and may remain
plaintext. The separate OfflineOTP `.json.aes` interchange remains encrypted
with its own export/import passphrase and is not the LinSCP application backup.
The application backup uses an independent password and an authenticated
Argon2id/AES-256-GCM envelope. It is distinct from the encrypted Key/Session
Export. The GUI offers **Options → Full application backup…**: unlock the
vault and enter a separate password of 12–1024 UTF-8 bytes. GUI exports are
limited to 16 MiB. WebView downloads, particularly on Android, require device
verification. The backup does not include active connections, transfer queues
or reconnect intentions.

Full application restore is available in the GUI (**Options → Full application
backup…**) and in the console (`backup import <file>`). Restore requires an
unlocked local password vault, explicit replacement confirmation in the GUI,
and quiescent connections and transfer queues. Key/Session Import is a separate
selective merge feature; it is not a full application restore.

Key/Session Export & Import (**Session → Key/Session Export…** and **Session →
Key/Session Import…**) selectively exports and merges chosen saved sessions
(including attached destination and jump-host SSH keys) in an encrypted
`LSCPVLT2` (OfflineOTP-compatible) archive. Scanning a backup returns a SHA-256
`fingerprint` verified on import so changing the file after scanning requires
re-reading before importing. Paired `SSH_KEY` records attach to their matching
sessions, and unpaired `SSH_KEY` records merge into SFTP sessions with their
vault-encrypted SSH keys attached. Vault SSH key imports reject accidental
public-key (`.pub` / SSH2 / PEM SPKI) uploads, opportunistically derive `.pub`
metadata for unencrypted OpenSSH/PEM/PuTTY `.ppk` private keys, preserve
`.label` metadata, and deduplicate identical private keys in `keys/` across
direct uploads, session saves, and `replace` imports.

Console `backup export <file>` and `backup import <file>` require
`LINSCP_BACKUP_PASSWORD` in the application process environment (at least 12
UTF-8 bytes); do not put it in command arguments or shell history. Environment
variables may be visible to privileged processes or inherited by child
processes. Save the backup password separately: without it the backup cannot be
opened. Only encrypted `LSCPBAK1` application backups are accepted.

Full application backups include saved sessions, all vault SSH keys (including
unreferenced keys and their label/public-key metadata), workspaces, bookmarks,
preferences, accounts, SSH host keys, explorer commands, custom commands,
monitor settings, and transfer presets, and record whether each optional
settings file exists. Restore removes optional files that were absent in the
backup and clears the destination's previous auto-reconnect intentions, which
are device-local activity state rather than portable settings.

Vault SSH keys (`keys/<id>.key.vault`), vault TLS certificate/CA/key blobs
(`keys/<id>.tls.vault`), and session secrets are decrypted in memory from the
backup and re-encrypted under the destination's existing unlocked vault key so
the destination vault password and `sessions.key` remain unchanged. Saved-session
and tunnel references retain their IDs. Existing keys are never overwritten: a
conflicting key ID or mismatched key material causes restore to fail before any
files are modified; identical keys retain their existing destination metadata.
Missing or corrupt referenced keys cause export or restore to fail closed.

Before mutating any configuration file, restore writes and syncs an
authenticated encrypted undo journal (`.full-restore-journal`) under the
destination vault key, publishes newly imported vault keys and syncs `keys/`
and `config_dir` before updating `sessions.ini` and the remaining stores, and
removes the journal only after the restored directory state is flushed. If a
crash or forced termination interrupts restore before commit, restarting LinSCP
blocks configuration access until the vault is unlocked and rolls back all
managed stores before removing newly published vault keys. Keep an independent
recovery copy before restoring, and do not modify the configuration directory
with external editors or older clients that do not honor `config.lock`.

Choose a strong, unique vault password and keep a separate encrypted
OfflineOTP credential export as a recovery copy. There is no password-reset
mechanism: losing the password means the wrapped master key cannot be opened;
recovery requires a separate usable backup (for example, the sensitive LinSCP
application backup or an OfflineOTP export). Malware running as the
same user (or an administrator/root process) can read credentials from process
memory or intercept them while the vault is unlocked; this design protects data
at rest, not an actively compromised account.

## Concurrent instances

`CommanderService` holds an advisory `config.lock` (`ConfigDirectoryLock`) for
its lifetime, preventing a second participating service instance or standalone
`backup import` from modifying the same configuration directory concurrently.
Vault-key deletion also checks stored sessions, including tunnel keys, under an
in-process lock and refuses keys currently referenced by them. Advisory locking
cannot stop external editors or older binaries that do not acquire
`config.lock`; do not edit configuration files externally while LinSCP is
running. Original key files and backups are not deleted by the vault picker.

### Saved-session metadata and migration

When the local password vault is unlocked, the application encrypts the entire
saved session store (including names, primary and alternate hosts, reconnect
settings, and other fields) with the vault key using authenticated encryption.
Reconnect restore intentions are encrypted as well. Existing plaintext stores
are validated and atomically replaced on unlock; an unreadable store causes
unlock to fail rather than being overwritten. Locking prevents reading or
writing these encrypted files. Older clients and the native CLI that do not
unlock the local password vault cannot read them and must not be used to edit
those files. Migration cannot erase plaintext from old backups, filesystem
snapshots, deleted blocks, or copies made before migration.

Workspaces and SSH host-key records are also encrypted under the unlocked
vault key, with different authenticated contexts. Legacy plaintext files are
validated and atomically migrated on unlock. Older clients cannot read them;
plaintext left in old backups, snapshots or deleted disk blocks is not erased.
Bookmarks and other configuration stores are not covered by this protection and
may still reveal identifying information.

The Commander log panel is held in process and browser memory rather than
intentionally persisted; owned backend log strings are wiped on eviction, vault
lock and normal service destruction. Browser/runtime copies, clipboard copies,
swap, operating-system crash dumps, forced termination and external process logs
cannot be guaranteed to be securely erased. Old log files and copies made by other
software are not automatically removed.
