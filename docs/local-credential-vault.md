# Local credential vault

LinSCP's Commander UI now requires a separate local-vault password at each
launch. The password is not saved. A random 256-bit data-encryption key remains
in process memory only after setup/unlock; `sessions.key` stores that key
wrapped with AES-256-GCM. The wrapping key is derived from the password with
Argon2id (64 MiB, three iterations, one lane) and a random salt. Existing
legacy `sessions.key` files are upgraded in place on first setup without
changing the key used to decrypt existing saved-session passwords.

Saved session passwords continue to use LinSCP's encrypted `sessions.ini`
format with the random data key. SSH private-key files that LinSCP imports or
copies into its saved-session store are encrypted with AES-256-GCM under that
same in-memory key. Their session values are opaque `vaultkey://` references;
for an SSH connection LinSCP creates a private, short-lived temporary key file
and removes it when the connection attempt returns. Explicitly locking the
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
