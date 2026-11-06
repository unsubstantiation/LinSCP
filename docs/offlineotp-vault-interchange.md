# LinSCP ↔ OfflineOTP credential-vault interchange

This document specifies LinSCP's portable encrypted credential file for future
exchange with OfflineOTP. The Rust codec is in
`crates/linscp-engine/src/offlineotp_vault.rs`. It uses a LinSCP-specific,
versioned Argon2id/AES-GCM envelope; OfflineOTP's current PBKDF2-HMAC-SHA1
backup reader is not compatible with this envelope. The inner SSH key and login
payload conventions remain intentionally close to OfflineOTP's models so its
planned importer can support the new envelope and reconstruct LinSCP sessions.
The shared UI exposes the exchange under Options → Credential vault import / export,
backed by `POST /api/vault/export` and `POST /api/vault/import`.
Imports merge by default, skip already-saved session names, and can replace the
saved-session list when explicitly requested. SSH key files are written with
private permissions beneath LinSCP's config directory.

## Encrypted file

The file is named `otp_accounts_YYYY-MM-DD_HH-mm-ss.json.aes` (UTC, ASCII
numbers); the timestamp is part of the OfflineOTP backup filename convention.
Its bytes are:

```
[8-byte ASCII version marker: "LSCPVLT2"]
[16-byte random Argon2id salt]
[12-byte random AES-GCM nonce]
[ciphertext || 16-byte GCM authentication tag]
```

The password derives a 256-bit AES key using Argon2id v=19 with 64 MiB memory,
three iterations and one lane. These parameters are fixed by the `LSCPVLT2`
version marker. AES-256-GCM authenticates the version marker as associated data.
The decrypted document is UTF-8 JSON: a compact array of credential entry
objects using the `SSH_KEY` and `PASSWORD` payload conventions described below.
The password is never saved in LinSCP configuration. The versioned header is
intentionally distinct from OfflineOTP's current PBKDF2 framing; OfflineOTP
must add support for this KDF and envelope to import LinSCP exports.

The writer and reader enforce OfflineOTP's 16 MiB document and 2,000-entry
limits. A bad password, tag, or malformed credential entry rejects the import;
there is no partial import. Ordinary OTP, note, email, and password-archive
entries in a broader OfflineOTP backup are ignored by the credential importer.
Password rows with an unsupported non-empty URL are counted as ignored; rows
without a URL import as incomplete SFTP sessions that can be edited in LinSCP.

## Entry mapping

### SSH keys

An SSH key is an OfflineOTP `SSH_KEY` entry. Its `secret` is padded uppercase
Base32 of the following binary payload (UTF-8 byte counts, big-endian):

```
[u32 public-key byte length][public-key bytes]
[u32 private-key byte length][private-key bytes]
```

Either key may be empty, but not both; each is bounded to 32 KiB. Optional
connection fields use OfflineOTP's `ssh_host`, `ssh_port`, `ssh_username`, and
`ssh_password` properties. `ssh_password` means the server login password, not
the private-key passphrase. LinSCP never invents or exports a private-key
passphrase as a login password.

### Login records

A login is an OfflineOTP `PASSWORD` entry. Its `secret` is padded uppercase
Base32 of OfflineOTP's `PasswordMaterial` framing:

```
[u32 0x50574431: "PWD1"][u32 field count]
repeat field count times:
    [u32 UTF-8 name length][name][u32 UTF-8 value length][value]
```

The first fields are `url`, `username`, and `password`. LinSCP-specific fields
use the `linscp_` prefix so OfflineOTP's existing password-entry model can
preserve them as ordinary additional columns:

- `linscp_session_json` is the portable saved-session record (including
  protocol, remote directories, proxy/jump-host configuration and their credentials).
  Local directory paths, key/certificate file paths and unreadable ciphertext are omitted; key
  material is carried separately when it is an SSH key. The sensitive session
  data is protected by the enclosing encrypted backup. Export refuses settings
  containing credentials LinSCP cannot safely restore.
- `linscp_ssh_key_label` and `linscp_tunnel_key_label`, when present, identify
  the separate SSH_KEY entries carrying the main and jump-host key material.

This lets OfflineOTP retain connection context and a later importer reconstruct
LinSCP sessions without requiring OfflineOTP to interpret LinSCP's settings
today. On import, LinSCP writes private key material to fresh owner-only files
inside its config directory and never trusts a path from the backup. Field
names are unique case-insensitively; at most 64 columns and 64 KiB per field
are accepted, with a 4 MiB encoded payload limit per entry.

The generic OfflineOTP `SSH_KEY` and `PASSWORD` entries remain useful on their
own: users can inspect/copy stored keys and credentials in OfflineOTP even
before its LinSCP-specific importer is implemented. OTP-only clients may keep
the encrypted file as a backup but will not make SSH credentials usable until
they implement this importer.

## Security and compatibility

This is an encrypted portable backup, not a live synchronizing vault. Treat the
file as sensitive, transfer it securely, use a unique high-entropy passphrase,
and verify a test import before deleting the source data. A weak passphrase is
vulnerable to offline guessing. The passphrase does not protect credentials
while LinSCP or OfflineOTP is unlocked. The existing LinSCP full-configuration
backup is a separate format and is not this credential interchange format.

The inner entry encoding follows OfflineOTP's `VaultJson`, `EntryJson`,
`SshKeyMaterial`, and `PasswordMaterial` conventions. The outer encrypted
format is LinSCP-specific and requires an OfflineOTP-side Argon2id reader before
these files can be exchanged. OfflineOTP also needs its LinSCP-specific
import-and-session reconstruction UI and end-to-end tests.
