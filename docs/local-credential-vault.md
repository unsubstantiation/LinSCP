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
The pre-existing LinSCP application backup format is a different, portable
configuration bundle; it includes the unwrapped master key as base64 and must
itself be kept in a protected location. Restoring an application backup with a
different master key is refused from the Commander command console so the
password-wrapped local key is not silently replaced with plaintext.

Choose a strong, unique vault password and keep a separate encrypted
OfflineOTP credential export as a recovery copy. There is no password-reset
mechanism: losing the password means the wrapped master key cannot be opened;
recovery requires a separate usable backup (for example, the sensitive LinSCP
application backup or an OfflineOTP export). Malware running as the
same user (or an administrator/root process) can read credentials from process
memory or intercept them while the vault is unlocked; this design protects data
at rest, not an actively compromised account.

## Concurrent instances

Vault-key deletion checks stored sessions, including tunnel keys, and refuses
keys currently referenced by them. Coordination is currently within one
CommanderService instance only. Do not edit `sessions.ini` externally or run
multiple instances against the same configuration directory while changing
sessions or deleting keys: those writers are not protected by a shared
transaction or interprocess lock. Original key files and backups are not
deleted by the vault picker.

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

The portable backup format is **not encrypted**: exports contain session
metadata and the unwrapped master key. Store exports securely and remove old
copies as appropriate. Other data such as workspaces, bookmarks, host-key
records, transfer history, and connection logs are not covered by this session
store encryption and can contain hostnames or other identifying information.
