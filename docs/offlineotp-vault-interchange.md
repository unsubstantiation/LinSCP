# LinSCP ↔ OfflineOTP key/session interchange

This document specifies LinSCP's portable key/session backup format for future
exchange with OfflineOTP. The Rust codec is in
`crates/linscp-engine/src/offlineotp_vault.rs`. It uses a LinSCP-specific,
versioned Argon2id/AES-GCM envelope; OfflineOTP's current PBKDF2-HMAC-SHA1
backup reader is not compatible with this envelope. The inner SSH key and login
payload conventions remain intentionally close to OfflineOTP's models so its
planned importer can support the new envelope and reconstruct LinSCP sessions.

The UI exposes the exchange as two separate dialogs under the Options menu:

- **Key/Session Export** writes the backup of the saved sessions the user
  selects. It is backed by `POST /api/vault/export`.
- **Key/Session Import** reads a backup and restores the sessions the user
  selects. It is backed by `POST /api/vault/scan` (read-only listing) and
  `POST /api/vault/import`.

Both dialogs show a tick-list of sessions: the export lists the currently
saved sessions; the import lists the sessions found inside the chosen backup
file. Sessions the user does not tick are not exported or imported. A backup
made this way contains everything LinSCP knows about a session that is useful
elsewhere: protocol, host, port, username, server password, key password,
host-key and directory settings, proxy and jump-host configuration and their
credentials, and the SSH key material the session references.

Imports merge by default and skip already-saved session names. Ticking
"Replace saved sessions with the same name" overwrites the saved sessions
whose names appear in the selected import set; sessions that are not selected
(or not in the backup) are left untouched either way. Key material is written
to fresh owner-only files beneath LinSCP's config directory, and a path stored
in a backup is never trusted. A failure anywhere in the import (including a
key staged to disk) rolls the whole operation back.

## Encrypted file (default)

The file is named `key_session_YYYY-MM-DD_HH-mm-ss.json.aes` (UTC, ASCII
numbers). Its bytes are:

```
[8-byte ASCII version marker: "LSCPVLT2"]
[16-byte random Argon2id salt]
[12-byte random AES-GCM nonce]
[ciphertext || 16-byte GCM authentication tag]
```

The password derives a 256-bit AES key using Argon2id v=19 with 64 MiB memory,
three iterations and one lane. These parameters are fixed by the `LSCPVLT2`
version marker. AES-256-GCM authenticates the version marker as associated
data. The decrypted document is UTF-8 JSON: a compact array of credential
entry objects using the `SSH_KEY` and `PASSWORD` payload conventions described
below. The password is never saved in LinSCP configuration. The versioned
header is intentionally distinct from OfflineOTP's current PBKDF2 framing;
OfflineOTP must add support for this KDF and envelope to import LinSCP exports.

## Plain-text file (opt-in, off by default)

Key/Session Export offers a "Export without a password (plain text)" checkbox.
It is **off by default** and its label carries the warning that the exported
secrets will be readable by any software on the device. When ticked, the same
document that would otherwise be encrypted is written as
`key_session_YYYY-MM-DD_HH-mm-ss.json` (UTC, ASCII numbers) without any
envelope — UTF-8 JSON, readable by any text editor. The export dialog disables
the password fields and the export always names the `.json` file so a plain
backup can never masquerade as an encrypted one.

Key/Session Import detects the two formats by the presence or absence of the
`LSCPVLT2` magic marker, never by the file extension: encrypted backups require
the password they were made with; plain-text backups require none. The import
of a plain-text backup is otherwise identical — the same entry validation,
selection semantics and rollback apply. There is deliberately no plain-text
"auto" mode on export: producing a readable copy of the secrets always takes an
explicit tick.

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
  protocol, remote directories, proxy/jump-host configuration, their credentials
  and the saved key password).
  Local directory paths, key/certificate file paths and unreadable ciphertext are omitted; key
  material is carried separately when it is an SSH key. The sensitive session
  data is protected by the enclosing encrypted backup (or, for a plain-text
  backup, nothing — see the previous section). Export refuses settings
  containing credentials LinSCP cannot safely restore.
- `linscp_ssh_key_label` and `linscp_tunnel_key_label`, when present, identify
  the separate SSH_KEY entries carrying the main and jump-host key material.

This lets OfflineOTP retain connection context and a later importer
reconstruct LinSCP sessions without requiring OfflineOTP to interpret LinSCP's
settings today. On import, LinSCP writes private key material to fresh
owner-only files inside its config directory and never trusts a path from the
backup. Field names are unique case-insensitively; at most 64 columns and 64
KiB per field are accepted, with a 4 MiB encoded payload limit per entry.

The generic OfflineOTP `SSH_KEY` and `PASSWORD` entries remain useful on their
own: users can inspect/copy stored keys and credentials in OfflineOTP even
before its LinSCP-specific importer is implemented. OTP-only clients may keep
the encrypted file as a backup but will not make SSH credentials usable until
they implement this importer.

The writer and reader enforce OfflineOTP's 16 MiB document and 2,000-entry
limits. A bad password, tag, or malformed credential entry rejects the import;
there is no partial import. Ordinary OTP, note, email, and password-archive
entries in a broader OfflineOTP backup are ignored by the credential importer.
Password rows with an unsupported non-empty URL are counted as ignored; rows
without a URL import as incomplete SFTP sessions that can be edited in LinSCP.

## HTTP endpoints

- `POST /api/vault/export` with `{ "password": string, "plain_text": bool,
  "sessions": [string] }`. `sessions` is the explicit list of saved-session
  names to export and is required to be non-empty when present; omitting it
  exports everything (kept for API compatibility with the previous release).
  `password` may be empty only when `plain_text` is true. Answers
  `{ "success": true, "filename", "data_base64", "entry_count", "plain_text" }`
  with a timestamped `key_session_*.json.aes` (encrypted, default) or
  `key_session_*.json` (plain text) filename. The export refuses a session
  whose saved secrets cannot be read safely, names the offending session and
  exports nothing rather than producing a partial file.
- `POST /api/vault/scan` with `{ "password": string, "data_base64": string }`
  and answers with the sessions a backup contains, each marked with
  `has_password` / `has_key_passphrase` / `has_ssh_key` / `exists_in_store`.
  Secret material is never returned to the page. Used to render the import
  tick-list.
- `POST /api/vault/import` with `{ "password": string, "data_base64": string,
  "replace": bool, "sessions": [string] }`. `sessions` selects which backup
  sessions are imported (non-empty when present; omitting it restores
  everything, kept for API compatibility). The format is auto-detected by the
  `LSCPVLT2` marker: encrypted backups need their password; plain-text
  backups need none. `replace` overwrites same-named saved sessions but never
  touches sessions outside the selection.

## Security and compatibility

This is a portable backup, not a live synchronizing vault. Treat the file as
sensitive — a plain-text export is readable by any software on the device —,
transfer it securely, use a unique high-entropy passphrase, and verify a test
import before deleting the source data. A weak passphrase is vulnerable to
offline guessing. The passphrase does not protect credentials while LinSCP or
OfflineOTP is unlocked. The existing LinSCP full-configuration backup is a
separate format and is not this interchange format.

The inner entry encoding follows OfflineOTP's `VaultJson`, `EntryJson`,
`SshKeyMaterial`, and `PasswordMaterial` conventions. The outer encrypted
format is LinSCP-specific and requires an OfflineOTP-side Argon2id reader
before these files can be exchanged. OfflineOTP also needs its LinSCP-specific
import-and-session reconstruction UI and end-to-end tests.
