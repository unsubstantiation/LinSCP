# Remaining parity implementation plan

> **Historical:** This plan predates the native GUI-only conversion; removed CLI interfaces are not planned for restoration.

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

90 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## sftp.native-session

**Area:** SFTP · **Status:** partial

Native libssh SFTP session refuses bad credentials and unexpected SSH host keys.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sftp.directory-crud

**Area:** SFTP · **Status:** partial

Transfers, directories, renames, symbolic links (ln/symlink) and chmod use native SFTP requests rather than curl.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sftp.copy-data

**Area:** SFTP · **Status:** partial

Native copy-data replies are used when offered; a multi-source/recursive streamed fallback works when absent.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sftp.check-file-name

**Area:** SFTP · **Status:** partial

Server check-file-name is used for sha-256 and all documented hashes fall back to downloaded bytes when refused.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sftp.permissions-and-times

**Area:** SFTP · **Status:** partial

Octal and recursive symbolic chmod plus file and directory timestamp preservation (-preservetime=all) work against the live SFTP server.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## scp.curl-file-transfer

**Area:** SCP · **Status:** partial

The id is the row's history: an scp:// transfer is not curl's any more. The bytes go over an SSH exec channel running the server's own 'scp -f' and 'scp -t', with the rcp wire protocol spoken by the client - a timestamp header, a mode/size/name header, exactly the stated bytes and an acknowledgement per step, in both directions. Downloads stage through '.filepart' and are renamed when whole, uploads carry '-permissions' and '-preservetime', a tree goes through the recursive form of the protocol with an 'E' per closed level, and continuing a partial file is refused by name instead of attempted, because the protocol has no offset to continue from. ASCII conversion, masks, speed limits, progress and the interrupt behavior are the shared transfer path's and are checked here as well.

**Next:** No runnable suite evidences this: live-scp and script need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## scp.shell-directory-engine

**Area:** SCP · **Status:** partial

The directory engine runs `ls -l -a --full-time` in its own SSH connection and parses it with the shared long-listing parser: `.` and `..` are skipped, names with spaces are kept whole, symbolic links keep their link type, and dates are read with the offset the server prints them in. `stat` is `ls -l -d`, so a missing path is reported as missing. `cd` is `cd <path> && pwd`, so the working directory is the one the server actually entered. `open` resolves the home directory and the site's initial path in one command. A server whose `ls` has no `--full-time` and no `env` gets the plainer command rather than an error. Server-supplied rcp header names are rejected when they contain a dot entry or either path separator, matching the upstream traversal hardening at every recursion level.

**Next:** No runnable suite evidences this: live-scp needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## scp.command-and-metadata

**Area:** SCP · **Status:** partial

The commands upstream runs on the remote shell, and the metadata a shell can set that 'ls -l' can read back: mkdir, rmdir, rm (never '-f', so a path that is not there stays an error the server words), mv, chmod with the mode the script parsed, 'cp -p' for a server-side copy - with a server that has no 'cp' answered by streaming through the client instead - 'ln -s' for a symbolic link, 'touch -t' asked for in UTC for a modification time, and the rcp timestamp header for the time a transfer carries. Every path is quoted for a POSIX shell and a path holding a control character is refused instead of being sent, because a newline in a name cannot be told apart from the end of a listing line. A refusal arrives as the sentence the server printed, 'call' hands the rest of the line to that shell, and 'checksum' says plainly that the digest came from a downloaded file, this protocol having no server-side hashing to ask for. A relative rmdir operand is resolved against the current remote directory before it reaches the protocol layer, matching the upstream full-path fix.

**Next:** No runnable suite evidences this: live-scp needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## ftp.curl-transfer

**Area:** FTP/FTPS · **Status:** partial

curl handles authenticated FTP/FTPS downloads and uploads with .filepart staging and PTY progress reporting against live FTP and FTPS servers.

**Next:** No runnable suite evidences this: live-curl needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## ftp.listings-and-mlsd

**Area:** FTP/FTPS · **Status:** partial

Plain FTP is served by the native FTP engine, which asks for MLSD where the server advertises it: size, type, time and permissions come from the protocol instead of from an ls -l line each server formats its own way. MLST answers stat, a server that refuses MLSD falls back to LIST, FtpUseMlsd=0 asks for LIST from the start, and FtpUseMlsd=2 (require) fails the listing rather than returning one without the machine-readable facts. The ls -l parser is shared with the curl backend, which serves the LIST replies and every transfer.

**Next:** No runnable suite evidences this: live-curl needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## ftp.active-passive

**Area:** FTP/FTPS · **Status:** partial

FtpPasvMode picks the data connection the native engine opens: passive by default, EPSV first with PASV as the fallback, and FtpPasvMode=0 opens it from the client instead, binding a listener and telling the server where it is with PORT or EPRT. FtpForcePasvIp decides whose address a PASV reply may use - 0 the control connection's, 1 (the default) the reply's unless it is unroutable, 2 the reply verbatim - and FtpAccount answers a server that asks for an account name on top of the credentials.

**Next:** No runnable suite evidences this: live-curl needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## ftp.tls-policy

**Area:** FTP/FTPS · **Status:** partial

FTPS stays on curl, the TLS client of this build, and upstream's setting names drive it: ftps:// (Ftps=1) is implicit TLS on port 990, ftpes:// (Ftps=2 or 3 on an ftp:// URL) is explicit TLS through --ssl-reqd, MinTlsVersion and MaxTlsVersion become --tlsv1.x and --tls-max, TlsCertificateFile and TlsCertificateKeyFile become --cert and --key, CaCertificateFile and CaCertificateDir become --cacert and --capath, and PinnedPublicKey becomes --pinnedpubkey. A policy curl cannot honour, or one given to a protocol without TLS, is refused before the connection rather than dropped; hostkey='*' is the only value that turns certificate validation off.

**Next:** No runnable suite evidences this: live-curl needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## dav.propfind-and-stat

**Area:** WebDAV · **Status:** partial

Depth 0/1 PROPFIND parses collection type, size and modification time; stat distinguishes absent paths.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## dav.basic-crud

**Area:** WebDAV · **Status:** partial

MKCOL, PUT, GET, DELETE and refusal of nonempty collection removal work against the live server.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## dav.copy-and-move

**Area:** WebDAV · **Status:** partial

MOVE and COPY send absolute Destination URIs; a refused COPY falls back to a byte-exact stream.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## dav.escaped-paths

**Area:** WebDAV · **Status:** partial

curl URL paths, DAV href comparisons and Destination headers preserve spaces and literal %, ? and # in names.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## dav.locks

**Area:** WebDAV · **Status:** partial

'lock <file> [-timeout=SECONDS]' takes an exclusive write lock and keeps its token in the session; 'unlock <file>' releases it. Every later upload, delete and move of that path carries the token as the If header, so a second writer without it is refused with 423 and the locked file keeps its content. A server that does not implement LOCK answers 405 and the command prints that instead of reporting a protected write. Upstream's WebDAV backend sends no LOCK or UNLOCK at all, so this is a LinSCP extension.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## dav.dead-properties-and-preconditions

**Area:** WebDAV · **Status:** partial

'property <file> -set=NAME=VALUE' stores one dead property through PROPPATCH and 'property <file> -get=NAME' reads it back with a named-property PROPFIND; both use this client's own namespace (urn:linscp:properties), a name that would build invalid XML is refused before any request, and a property the server does not have prints 'NAME is not set' rather than failing. The conditional write is the lock token: PUT, DELETE and MOVE of a locked path send If, which is what makes the server refuse a write whose lock is gone (423).

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## s3.sigv4-auth

**Area:** Amazon S3 · **Status:** partial

Requests are signed with AWS Signature Version 4; absent or incorrect credentials fail against a TLS verifier.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## s3.bucket-object-listing

**Area:** Amazon S3 · **Status:** partial

ListBuckets, ListObjectsV2, HEAD and virtual directories are exercised against the test endpoint; malformed or repeated pagination state is an error rather than a partial directory listing.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## s3.small-objects-and-range-get

**Area:** Amazon S3 · **Status:** partial

PutObject, GET and a resumed HTTP byte-range download roundtrip.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## s3.multipart-upload

**Area:** Amazon S3 · **Status:** partial

Files over 16 MiB use initiate/parts/complete and abort on handled completion errors.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## s3.copy-object

**Area:** Amazon S3 · **Status:** partial

Single-object CopyObject, embedded HTTP-200 errors and rename-as-copy-plus-delete are tested.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## s3.multipart-restart-and-copy

**Area:** Amazon S3 · **Status:** partial

Interrupted multipart uploads persist completed part ETags in a local sidecar to resume remaining parts, and large server-side copies use multipart UploadPartCopy with byte ranges.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## s3.object-options

**Area:** Amazon S3 · **Status:** partial

S3 rawsettings configure signed x-amz-storage-class, x-amz-acl, x-amz-server-side-encryption, KMS key ID, x-amz-request-payer and custom x-amz-meta-* headers on uploads and copies.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## transfer.masks

**Area:** Transfers · **Status:** partial

Name/path/directory masks and size/time criteria filter transfers and synchronization.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## transfer.ascii-automatic

**Area:** Transfers · **Status:** partial

ASCII conversion is byte-checked through a live upload; automatic mode selects text files by mask.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## transfer.filepart-resume

**Area:** Transfers · **Status:** partial

Interrupted uploads/downloads stage in .filepart and continue there rather than splicing the final destination.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## transfer.resume-modes

**Area:** Transfers · **Status:** partial

Automatic/on/off and -resumesupport thresholds are parsed; resume-off transfers without staging.

**Next:** No runnable suite evidences this: live-sftp and script need a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## transfer.time-permissions

**Area:** Transfers · **Status:** partial

SFTP preserves file and directory timestamps (-preservetime=all) and applies -permissions modes on uploads and downloads.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## transfer.speed-and-append

**Area:** Transfers · **Status:** partial

Native SFTP supports -append without overwriting existing bytes and -speed= bandwidth throttling; curl uses --limit-rate and refuses append.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## transfer.presets

**Area:** Transfers · **Status:** partial

Named, per-site and rule-selected presets change live transfer settings.

**Next:** No runnable suite evidences this: live-dav and script need a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## transfer.curl-progress

**Area:** Transfers · **Status:** partial

curl-backed downloads and uploads stream curl's progress meter into the byte-progress callback and render live PTY progress percentages while staging downloads through .filepart.

**Next:** No runnable suite evidences this: live-curl needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## sync.one-way

**Area:** Synchronization · **Status:** partial

Local-to-remote keepuptodate and recursive one-way planning/upload run against the live WebDAV server.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sync.both-state

**Area:** Synchronization · **Status:** partial

A persistent state file distinguishes one-sided changes and deletions from two-sided conflicts and applies -conflict=skip|local|remote|newer against a live SFTP server.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## sync.checksum

**Area:** Synchronization · **Status:** partial

Checksum criteria find same-size/same-time changes and stop if contents cannot be hashed.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## sync.exclusions-delete-guard

**Area:** Synchronization · **Status:** partial

An excluded subtree is pruned from the plan and cannot be deleted at the destination.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sync.keepuptodate-inotify

**Area:** Synchronization · **Status:** partial

Nested local arrivals wake the recursive inotify watcher before the rescan interval.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sync.criteria-and-mirror

**Area:** Synchronization · **Status:** partial

Time/size/checksum criteria, -mirror and two-way conflict policies are validated in script and unit suites and exercised against a live SFTP server. The Commander's synchronize dialogue offers the same mirror as a one-way copy that deletes what the source no longer has, and its settings are held to the planner's own rules by a service unit test.

**Next:** No runnable suite evidences this: live-sftp and script need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## sessions.site-manager

**Area:** Sessions/configuration · **Status:** partial

Stored sites can be saved, opened, removed, exported and imported.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sessions.password-at-rest

**Area:** Sessions/configuration · **Status:** partial

Stored site passwords are encrypted under sessions.key and shared between the CLI and GUI. On Windows the configuration directory carrying sessions.key is additionally owner-only: `ensure_private_dir` applies `D:P(A;OICI;FA;;;OW)`, and children created inside inherit the ACE, because bypass-traverse-checking makes the directory's own ACE insufficient protection for the files.

**Next:** The encryption half has no runnable evidence: live-sftp needs a `linscp` binary this repo does not build. Runnable residue: platform-windows-acl on Windows covers the configuration-directory DACL only.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Cover the encryption half (sessions.key sealing and opening) with a runnable suite on all three platforms.

## sessions.vault-password-only

**Area:** Sessions/configuration · **Status:** partial

The vault is password-only on every build, and the tree finally says so: the never-wired DPAPI/Keystore constructors, decoder branches, Windows DPAPI functions, KeystoreBridge trait, and Tauri keystore state were removed instead of left as dead surface. sessions.key is LSCPVLT1 (Argon2id plus AES-256-GCM) with legacy raw/base64 migration, and the migration guide claims that described hardware wrapping as implemented now say it was removed or descoped.

**Next:** No Android step executes the Rust vault tests, so the password-only behaviour is unproven on device; and the doc corrections are prose, not runnable evidence.

**Acceptance criteria:**

- [ ] An emulator or device run executing the vault tests, or a native harness that runs Rust cases on Android.

## sessions.proxy-settings

**Area:** Sessions/configuration · **Status:** partial

Upstream proxy setting names are applied by open and stored with a site; both SOCKS5 and HTTP CONNECT proxies carry live SFTP sessions and refuse bad credentials.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sessions.rawsettings

**Area:** Sessions/configuration · **Status:** partial

'open' and 'savesession' take '-rawsettings' with upstream's names: the proxy settings (ProxyMethod, ProxyHost, ProxyPort, ProxyUsername, ProxyPassword, ProxyTelnetCommand, ProxyLocalCommand, ProxyDNS, ProxyLocalhost, ProxyExcludeList), the FTP engine's policy (FtpPasvMode, FtpForcePasvIp, FtpUseMlsd, FtpAccount) and the TLS policy (Ftps, MinTlsVersion, MaxTlsVersion, TlsCertificateFile, TlsCertificateKeyFile, CaCertificateFile, CaCertificateDir, PinnedPublicKey). A name or value outside that set is refused by name before any connection, so a setting is never stored and then dropped at open time, and 'savesession' writes what it applied under the keys a saved site reads back.

**Next:** No runnable suite evidences this: live-curl and script need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## security.native-hostkey

**Area:** Security/authentication · **Status:** partial

Native SFTP refuses an unknown/unexpected host key until it is pinned.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## security.password-key-agent

**Area:** Security/authentication · **Status:** partial

Password, unencrypted and passphrase-protected private-key (-passphrase=), ssh-agent and copyid public/private key installation work against the live SFTP server.

**Next:** No runnable suite evidences this: live-sftp and script need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## security.agent-android-refusal

**Area:** Security/authentication · **Status:** partial

Agent authentication explains itself when there is no agent to ask. The auth chain asks the connector for a missing reason when its stream comes back empty: SshAgentConnector gains a defaulted missing_reason, SystemSshAgentConnector answers with a platform reason (SSH_AGENT_MISSING_MESSAGE on Android, none where the build probes for a socket), and the reason becomes the terminal error instead of the generic auth failure. The site dialog shows the same story up front through a hostDifferenceReason-backed hint wired to a new bundle sshAgent flag; the hint fails open (any non-Android host is assumed to have an agent) because the page cannot see the server OS, so the backend refusal is the layer that cannot be skipped.

**Next:** The Android-Rust arm — the real connector reporting the platform message through the real chain — executes in no step: Android runs no Rust tests, and the emulator smoke does not attempt agent authentication. Message selection on device is review-level.

**Acceptance criteria:**

- [ ] An emulator or device run attempting agent authentication and showing the platform reason instead of the generic failure.

## security.curl-pins-and-tls

**Area:** Security/authentication · **Status:** partial

`-hostkey=` accepts the fingerprint spellings people paste: SHA-256 in hex (with or without `:`), `SHA256:base64`, curl's `sha256//base64`, and MD5 with or without the `MD5:` marker `ssh-keygen` prints. Both SSH engines compare it with the fingerprint the SSH core reports, so `sftp://` and `scp://` pins share one code path, and no pin depends on the installed curl. A key that does not match is refused. An unknown key in a run nobody can answer is refused with the key printed so it can be pinned, and a checked key is remembered. A TLS session keeps chain validation (the system store, or CaCertificateFile and CaCertificateDir) and pins the server's public key with `--pinnedpubkey`. A value curl cannot compare is refused, and only `*` disables the checks.

**Next:** No runnable suite evidences this: live-curl, live-scp, live-sftp, and script need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## security.proxy-isolation

**Area:** Security/authentication · **Status:** partial

SFTP SOCKS5 and HTTP CONNECT proxies and curl proxy routing are verified live; wrong proxy credentials and unsupported proxy modes are refused rather than bypassed.

**Next:** No runnable suite evidences this: live-dav and live-sftp need a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## security.gui-api-token

**Area:** Security/authentication · **Status:** partial

The local browser API rejects requests missing its per-run token.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

Authenticated SSH jump-host connections work for SFTP/SCP/SSH and for FTP/FTPS/WebDAV/S3 destinations. SSH destinations still use a private socketpair (or TunnelLocalPortNumber on loopback); curl and native FTP/S3 sessions start a loopback SOCKS5 multiplexer on the jump so each CONNECT or data channel is a separate direct-tcpip, TLS SNI and S3 signing keep the original hostname, and a refused forward never falls back to a direct connection. Kerberos/GSSAPI settings persist and gssapi-with-mic is attempted before public-key with password fallback; credential delegation stays off unless GSSAPIFwdTGT=1. GSSAPI authentication support is detected through libssh's public ssh_gssapi_set_creds symbol, not its version string. RFC 4462 KEX support is probed independently; AuthGSSAPIKEX is refused if the loaded libssh cannot honor it or a host-key pin is configured, rather than silently skipping either policy. The live SFTP suite provisions an isolated loopback MIT KDC and OpenSSH server and tests principal selection, missing/expired tickets, the service identity, and default-off versus opt-in TGT delegation. A second realm, PARTNER.TEST, is trusted directly through krbtgt/LINSCP.TEST@PARTNER.TEST. It covers cross-realm login, refusal of an unmapped principal of the trusted realm, and default-off versus opt-in delegation of the partner realm's TGT. CI requires a GSSAPI-enabled libssh and zero skips for these cases. As upstream's CreateTunnelData does, the jump session inherits the destination's Kerberos settings except LogicalHostName, so GSSAPIFwdTGT=1 also delegates to the jump host. docs/gssapi-delegation-review.md is the brief for the independent review; that review and production-KDC validation remain open. On Linux the GUI settings now flow to a real GSSAPI attempt (the parser used to drop all four Kerberos keys); on Windows and Android the site manager labels the section Linux-only, key exchange is noted as unsupported on every build, and explicit settings fail closed naming the requirement. The Windows and Android citations below evidence that labeling and refusal, not Kerberos authentication itself.

**Next:** Production-KDC validation (for example Active Directory, FreeIPA or Heimdal) and an independent security review of opt-in TGT delegation remain outstanding; the review brief is docs/gssapi-delegation-review.md. The isolated CI realms already cover a direct cross-realm trust. Windows has no SSPI backend, so Kerberos authentication is Linux-only; the site manager says so and explicit settings fail closed.

**Acceptance criteria:**

- [ ] Run the isolated-realm GSSAPI cases in CI with a GSSAPI-enabled libssh and no skipped cases; cover principal selection, missing/expired credentials, service mutual authentication, default-off delegation and opt-in TGT delegation.
- [ ] Obtain an independent security review of delegated TGT handling and validate cross-realm/production-KDC behavior before claiming general Kerberos parity.
- [ ] Provide a Windows SSPI (or sspi-crate) context provider behind the GssapiTokenProvider trait, with tests against an AD or Samba KDC, before claiming Kerberos on Windows.

## security.gui-account

**Area:** Security/authentication · **Status:** partial

Optional account login isolates each signed-in user at the application layer: PBKDF2 password hashes, session expiry, per-login CSRF tokens and login throttling, plus per-user tabs, transfer queues, logs, terminals, sessions.ini/workspaces and a home_dir jail for every local filesystem and command-execution route. This is a LinSCP server-deployment extension, not a feature of the upstream desktop client. The process still runs as one OS user; mutually hostile callers should use separate OS accounts. Negative authorization tests cover every API route, not just login.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## gui.native-path-drop

**Area:** GUI · **Status:** partial

An operating-system drop in a native window arrives as paths, not as a File: `dragDropEnabled` makes the Tauri window consume the drop before the page sees it. The shell emits `native:file-drop` with those paths, the shared bundle turns them into one request (the first path plus the list, with the folders named), and the service stages and queues exactly what the browser's byte drop would - the same endpoints, the same queue, the same conflict answer, so one set of overwrite rules answers for all three apps. A local drop copies the tree directly; a grant-URI source is read through `LocalFs`; a link inside a dropped folder is refused rather than followed. Android's share hand-off records the desktop's pending manifest and the page queues it through the same path. What the drop still lacks is end-to-end evidence on a real window: the jsdom suite drives the request shape and the service test drives the filesystem, but neither can produce a WebKit drop event, and the share intent filter is registered by the generated Kotlin project rather than by this tree.

**Next:** The path a native window drops is queued and copied, but no test drives a real WebKit drop event or the Android share filter, and a large dropped folder is staged in the app's private directory with no bound on the space it takes.

**Acceptance criteria:**

- [ ] Drive a real WebKit/GTK drop onto the native window and show the queued task names the dropped paths (the shell's `dragDropEnabled` handler cannot be exercised by jsdom).
- [ ] Register the Android share intent filter in the generated Kotlin project and prove a shared file reaches the same drop path, including the conflict question and the queue entry.
- [ ] Prove a dropped folder larger than memory is staged without holding it in the page, and that a partial staging tree is removed when the queue refuses the drop.

## editing.local-editor

**Area:** Editing/search · **Status:** partial

GUI reads text and saves locally with a conflict check and atomic replace; symlinks are refused.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## editing.filename-and-content-search

**Area:** Editing/search · **Status:** partial

Filename search and bounded literal UTF-8 content search skip binary/oversized files and cap the scan.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## editing.monitor-local-changes

**Area:** Editing/search · **Status:** partial

'edit -monitor' watches the temporary local file while the external editor remains open and uploads each save after verifying the remote file was not modified concurrently.

**Next:** No runnable suite evidences this: live-sftp needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## editing.encoding-policy

**Area:** Editing/search · **Status:** partial

The browser editor and search enforce UTF-8 text and reject binary files, while CLI 'edit -eol=lf|crlf' normalizes line endings before upload.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## automation.command-interpreter

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## automation.parameter-and-timestamp

**Area:** Automation · **Status:** partial

%1%..%9%, timestamp formats and environment expansion follow tested script behavior.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## automation.literal-gui-command

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## automation.xml-action-log

**Area:** Automation · **Status:** partial

The XML action log (-xmllog=) writes the upstream session format (http://winscp.net/schema/session/1.0): '<group>' per command and structured '<upload>', '<download>', '<rm>', '<mkdir>', '<mv>', '<cp>', '<chmod>', '<touch>', '<call>', '<ls>', '<stat>', '<checksum>' and '<cwd>' elements with '<result success>' children and secrets masked. Schema and consumer equivalence are automation.upstream-xml-compatibility.

**Next:** No runnable suite evidences this: live-sftp and script need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## automation.dotnet

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## automation.powershell

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## desktop.scheme-handlers

**Area:** Desktop integration · **Status:** partial

The desktop entry and GUI parse sftp://, ftp://, ftps:// and ftpes:// startup URLs with escaped paths.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## desktop.launcher-prefix

**Area:** Desktop integration · **Status:** partial

Installed, Makefile and CMake binaries select their own GUI launcher; the GUI finds the matching core under a relocatable prefix.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## desktop.wayland-session

**Area:** Desktop integration · **Status:** partial

A desktop session is recognised as Wayland or as X11 before anything is asked of it, and only a program that can draw on it is started. The console client finds the compositor by its socket in XDG_RUNTIME_DIR - the default 'wayland-0' when WAYLAND_DISPLAY is not exported, so a session started by a launcher or a user service is still found - and refuses a Wayland-only terminal under X11, where it exits before mapping a window, while an X11-only one under Wayland is a reported XWayland fallback rather than a silent choice. The graphical client draws no window itself and asks the desktop's own URI launcher ($BROWSER, xdg-open, gio) for a browser, which needs no X11 and no window manager of the X11 kind; linscp.desktop starts it with that option and does not claim a startup notification it could never complete. Covered by unit, the retired GUI harness and wayland-compatibility; no case runs against a live compositor, so the interaction with one is not certified here.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] wayland-compatibility cannot run on Windows or Android (it is a Linux display-server guard); record platform-scoped evidence for the Linux-only behavior, or cite additional runnable suites there.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English, Spanish, German and French catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client, including the external-editor prompts. The translation compiler rejects a message that reaches the user without a catalog entry. A catalog walker reports interface strings still answered in English so a new string cannot slip through untranslated, and the translation tests keep switches, values, command names and protocol words literal in every catalog. The language selector and the backend's locale selection are filled from the shipped catalogs, and a confirmation accepts the yes letter its translated hint shows. Only English, Spanish, German and French catalogs are shipped; upstream ships catalogs for many more languages.

**Next:** Only English, Spanish, German and French catalogs are shipped; upstream ships catalogs for many more languages, and the upstream .NET interface has strings that this client does not have at all. No full upstream language-catalog coverage is claimed. A walker already reports catalog messages still answered in English.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.

## platform.make-linux

**Area:** Packaging/platforms · **Status:** partial

source/linux/Makefile builds the native Linux/libssh client, refuses non-Linux hosts and provides an install target staged under DESTDIR/PREFIX.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.cmake-linux

**Area:** Packaging/platforms · **Status:** partial

CMakeLists.txt builds the Linux binaries, registers CTest suites, refuses non-Linux hosts and installs the CLI, GUI, desktop entry and man page.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.debian-package

**Area:** Packaging/platforms · **Status:** partial

debian/rules and debian/control package the CLI, GUI, desktop entry, icons and man page matching the staged Linux install tree.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.prefix-lookup

**Area:** Packaging/platforms · **Status:** partial

An arbitrary PREFIX/share/linscp/gui resolves PREFIX/bin/linscp before /usr/bin.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## platform.posix-runtime-services

**Area:** Packaging/platforms · **Status:** partial

The Linux platform layer supplies temporary directories, home/config lookup and concurrent child stdout/stderr capture.

**Next:** No runnable suite evidences this: unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## platform.terminal-and-console

**Area:** Packaging/platforms · **Status:** partial

Linux command-line parsing, terminal-facing configuration and the native console entry point are built from the Linux sources. Which terminal 'terminal' starts depends on the display server the session runs on; that behavior is its own row, desktop.wayland-session.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## platform.linux-file-events

**Area:** Packaging/platforms · **Status:** partial

The Linux synchronization watcher uses filesystem events and retains interval polling as a safety net when a watch cannot be installed.

**Next:** No runnable suite evidences this: live-dav needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.conversion-completeness

**Area:** Packaging/platforms · **Status:** partial

LinSCP is a Linux-only client and the check that says so is part of the build: tools/check_platform_conversion.py reads the client's own sources and refuses a Windows API call, a Windows header, a Windows-only compilation branch, a Windows environment variable, a Windows executable, a Windows path, a file of another platform, an installer that does not ship what the other installers ship, and an error message whose operation phrase contradicts the template it is filled into. It runs in 'make -C source/linux check', as the CTest case 'platform-conversion-check', and in CI. Third-party code is not scanned; everything else in the tree is this project's own.

**Next:** Runnable evidence exists on Linux only (platform-conversion); Windows and Android have none (see the suite registry).

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Extend the runnable residue (platform-conversion) to Windows and Android, or cite additional runnable suites there.

## platform.android-saf-editing

**Area:** Packaging/platforms · **Status:** partial

Opening, saving and reading properties in a granted Android folder go through LocalFs to the SAF bridge instead of the refusal: the editor reads the document bytes, saves create-or-replace the document, and properties rows carry the bridge's stat, on the main pane and on a granted other pane alike. The stale-save guard compares at the bridge's seconds precision, the same granularity remote saves use. A save whose stat fails proceeds to the bridge write, because a missing document and an unreadable one are indistinguishable there and the write creates what is missing; a genuinely broken write still surfaces its own error. The page offers the editor for granted folders again; chmod, synchronization, transfers, copy/move and watching keep their named refusals (see platform.android-saf-refusals).

**Next:** No suite has touched a real DocumentsProvider: the bridge is an in-memory mock, so provider behaviour (mtime precision, create-or-replace error cases, large documents) is unproven on a device.

**Acceptance criteria:**

- [ ] Open, edit, save and re-read a file in a granted folder on an Android device or emulator, covering the stale-save refusal and the properties rows the dialog shows.

## platform.android-saf-local-copy-move

**Area:** Packaging/platforms · **Status:** partial

Local copies and moves with a granted end run on LocalFs in the queue worker: bytes cross the bridge whole between plain and granted panes and between two granted trees, with the same conflict policies as plain pairs. Every granted move is a copy that deletes its source (queue jobs always carry the same leaf on both sides, so a provider-side rename could only retarget a name onto itself); same-directory renames stay on the rename endpoint, which renames directly. Files over the 64 MiB document cap refuse at enqueue time and in the worker naming the file; symbolic links refuse by name; a plain target keeps the source's seconds while a granted target gets fresh stamps, and directory copies keep the plain panes' refusal word for word. The page offers transfers and moves on local tabs and still gates session transfers and moves on remote tabs.

**Next:** No suite has touched a real DocumentsProvider: the bridge is an in-memory mock, so provider behaviour (nested document URIs, large-document memory pressure, concurrent-creator races on moves) is unproven on a device.

**Acceptance criteria:**

- [ ] Copy and move files between a granted folder and app storage and between two granted trees on an Android device or emulator, covering the document-cap refusal and a move onto an existing name.

## platform.android-saf-session-transfers

**Area:** Packaging/platforms · **Status:** partial

Session transfers with a granted local side stage through private temporary files in the queue worker: uploads stage the granted source (keeping its seconds, so the remote keeps its stamps) and run the guarded upload unchanged from the stage; downloads land in a stage and publish across the bridge file by file. Trees stage and publish whole in both directions; merges add to an existing granted tree without replacing any file and fail instead of replacing. Files over the 64 MiB document cap refuse at enqueue time naming the file; verified resume refuses for granted folders, since the bridge has no appends or partial files; WebDAV moves delete the remote source by ETag after the staged download publishes. The page offers transfers and moves for granted folders on both tab kinds.

**Next:** Both remotes are in-memory mocks: no suite has uploaded from or downloaded into a real DocumentsProvider, so provider behaviour (nested document URIs, large-document memory pressure, concurrent writers during a merge) is unproven on a device.

**Acceptance criteria:**

- [ ] Upload, download and move files between a granted folder and a server on an Android device or emulator, covering a tree transfer, the document-cap refusal and the resume refusal.

## ftp.non-unix-listings

**Area:** FTP/FTPS · **Status:** partial

Shared LIST parser handles Unix long listings, DOS/IIS listings (MM-DD-YY[YY] HH:MM[AM|PM] <DIR>/size with spaces in names, date/size variants) and VMS listings (name;version size DD-MON-YYYY HH:MM:SS [OWNER] (RWED,RWED,RE,RE) with directory detection via .DIR extension and protection-field permissions). MLSD provides machine-readable alternative; DOS/VMS malformed-input is rejected and treated as empty rather than silently succeeding, and LIST fallback is exercised against live servers that emit the supported formats. Other non-Unix dialects remain undocumented as unsupported.

**Next:** No runnable suite evidences this: live-curl needs a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## dav.etag-preconditions

**Area:** WebDAV · **Status:** partial

'etag <file> -match=ETAG' records an If-Match precondition and '-nomatch=ETAG' an If-None-Match one, per path and per session; '-get' reads the current tag with a Depth-0 PROPFIND and tells a missing path apart from a server that reported no tag; '-clear' forgets a recorded one. A WebDAV upload, delete or move of that path carries the tag in the If header, in one no-tag condition list together with a lock token when the path is also locked - '(<opaquelocktoken:...> ["tag"])' - because RFC 4918 reads an If header as either no-tag lists or tagged lists and never as both, and the token has to be the Coded-URL of angle brackets a standard server looks for. '-nomatch=' is sent as '(Not ["tag"])': a list without the Not would have been If-Match, the opposite of the documented 'write only if the version differs'. The value travels quoted as the entity tag the server gave - 'etag -get' prints "abc", the command splitter strips those quotes, and DavEntityTag puts them back with a W/ weakness prefix left outside them - and '*' is refused by name instead of sent, since an If header has no way to say 'only if absent' and a quoted asterisk is a tag no resource carries, which would guard nothing while looking like a guard. DAV response text is XML-unescaped on the way in, so an escaped getetag arrives as the tag it is rather than as '&quot;...&quot;', which no precondition could ever match. Against a live server a matching tag writes, a stale one is refused with 412 and leaves the destination's bytes and its collection listing exactly as they were, If-None-Match writes where the version differs and is refused where it does not, an absent resource answers it, and a 412 on MOVE says which of its two causes it was rather than always blaming an existing destination. Collection semantics are defined rather than inherited: a precondition guards the path it was recorded for and nothing below it, because a collection's tag names its listing - the first member written under an inherited one would stale it and fail every later write in that directory. A session whose protocol has no entity tags (the SSH engines, FTP, S3) is refused by name, '-get' included, rather than left believing a later write is conditional. Upstream's WebDAV backend sends no ETag precondition at all, so this is a LinSCP extension.

**Next:** No runnable suite evidences this: live-dav and live-sftp need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## s3.versioned-objects

**Area:** Amazon S3 · **Status:** partial

`versions` lists exact-key or prefix history and delete markers through guarded ListObjectVersions pagination; `get -versionid=` reads one version, HEAD metadata handles delete markers, and resumable staging uses an ID-specific suffix; `rm -versionid=` deletes only the named version/marker. Live tests cover opaque query characters, a 1001-record two-page history plus missing/repeated pagination-marker refusals, historical/current downloads, isolated resume staging and marker creation/removal without losing other versions.

**Next:** No runnable suite evidences this: live-s3 needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## editing.non-utf8-encodings

**Area:** Editing/search · **Status:** partial

CLI editing supports explicit legacy-encoding selection via iconv (ISO-8859-1, Windows-1252, EUC-JP, Shift-JIS, UTF-16 etc.): 'edit -encoding=ENC' converts between the file's encoding and UTF-8, round-tripping byte-exact fixtures with BOM/EOL preservation, and rejects invalid sequences or unrepresentable output without silent replacement. Browser editor/search remain UTF-8-only and reject binary/non-UTF-8 files with an explicit message; the encoding contract is documented and tested.

**Next:** No runnable suite evidences this: unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## automation.upstream-xml-compatibility

**Area:** Automation · **Status:** partial

The XML action log (-xmllog=) now writes the upstream session format instead of a look-alike: root '<session xmlns="http://winscp.net/schema/session/1.0" name="user@host"|site|nosession start="...Z">', one '<group>' per script command named by its masked line (grouping is always on, so a continuous reader knows a command finished when its group closes), one element per physical operation - upload, download (both with '<size>'), rm (including rmdir and S3 exact-version removal), mkdir, mv, cp, chmod ('<permissions>' as 'rwxr-xr-x' letters), touch ('<modification>'), call ('<output>'/'<erroroutput>' streams and '<exitcode>' from a captured run), ls ('<files>' of '<file>' with the upper-case type character), stat (one '<file>' with no '<filename>'), checksum ('<algorithm>'/'<checksum>') and cwd - each ending in '<result success="true|false">' with '<message>' on failure, and a '<failure>' with the command's masked errors closing a failed group. Attribute and text escaping follow upstream's XmlAttributeEscape/XmlEscape pair (newline as '&#10;' in attributes, CR and unrepresentable controls dropped), timestamps are the one UTC '....NNNZ' spelling. The format is pinned in the repository as docs/linscp-session-1.0.xsd, written from upstream's emitter (source/core/SessionInfo.cpp) and its XML Logging documentation. The script suite validates the shipped fixtures (fixtures/xml/) and freshly produced logs against that schema with xmlschema - including a masked-password failure - and reads operations back the way an upstream-style consumer does; the live SFTP suite validates a full real session log the same way and checks every action element's parameters against the bytes it moved. Boundaries kept: console output is not recorded (as upstream), operations with no upstream element (symlink creation) are absent (as upstream), 'difference' elements for a bare synchronization comparison are schema-defined but only emitted through the transfer/mkdir/rm elements a synchronization actually performs, and a run that never connects keeps the upstream fallback session name 'nosession'.

**Next:** No runnable suite evidences this: live-sftp and script need a `linscp` binary this repo does not build; unit has no build target and cannot be compiled.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## gui.local-to-local

**Area:** GUI · **Status:** partial

A local-to-local session is a tab whose protocol is 'local' and which names two absolute local directories (the upstream IsLocalBrowser/OtherLocalDirectory shape). CoreSession.start, connect and alive never spawn the core and never open a socket; the right pane lists its directory through the same API the remote pane uses. Copies and moves are planned and run in-process on the queue with byte progress and cancellation: recursive trees, merge into an existing directory, atomic per-file replacement through a temporary file, timestamps and modes preserved, symbolic links copied as links, and ask/skip/overwrite/rename decisions (the browser answers 'ask' once and retries). Source equal to or inside the destination is refused before queueing. The second pane also supports mkdir, rename, delete, chmod, properties, checksums, editor save and find. The server-only terminal, synchronization and remote transfer dialogs are not offered in this mode.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## gui.local-symlink

**Area:** GUI · **Status:** partial

Symbolic links can be created in a local pane, not just over SFTP: the other pane of a local tab goes through a new local branch in link_remote_async, the main pane through a new /api/local/link endpoint, and both share one helper (create_local_link) that validates two different single-leaf names, refuses a taken link name, and calls gui_os.create_local_symlink after resolve_contained. The page dialog is one pane-aware promptLink(side), offered from the Local menu for the local pane and the Commands menu for the remote pane with no new translatable strings; a granted folder is refused by the shared app-storage message in both layers.

**Next:** Link creation itself is proven only on Unix: the creation test is cfg(unix) because Windows needs a symlink privilege (or developer mode) this suite cannot grant itself, and Android runs no Rust tests. Validation and the granted-folder refusal run on every platform.

**Acceptance criteria:**

- [ ] A Windows CI run proving link creation in a plain directory, or a documented privilege requirement the backend reports.
- [ ] A device or emulator run proving link creation in Android app storage.

## sessions.workspaces

**Area:** Sessions/configuration · **Status:** partial

Named workspaces are stored in workspaces.json beside sessions.ini (0600, fsynced and atomically replaced) and restore the tabs in order with the saved active tab and both pane paths. An entry is either a local tab with its two directories or a remote tab; a tab that came from a stored site records only the site name and is resolved from sessions.ini on every open, so the site's password encryption, pinned host key and tunnel policy stay authoritative. An ad-hoc tab is saved as a snapshot with password, tunnel password, tunnel passphrase and site name removed. Each tab opens independently: a deleted or renamed site, a missing local directory or a host-key challenge is reported in 'failed' without stopping the others, and a challenge is parked in the normal host-key table for the user to verify. A local site can be saved directly, since the console client has no local transport.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## gui.remote-delete

**Area:** GUI · **Status:** partial

The panes' delete runs on the session: each selected name is validated as a leaf, joined to the panel directory and removed with the queue's own tree walk, which empties a directory before removing it and unlinks a symbolic link instead of following it. A name the server no longer has counts as deleted; a refusal is reported per name, and the valid names of the same request still run. A local tab keeps its contained path resolution. It is not transactional: an interruption can leave part of a tree, which the row states as its gap.

**Next:** Remote deletion is not transactional: a directory is emptied before it is removed, so an interruption can leave part of a tree.

**Acceptance criteria:**

- [ ] Prove an interruption leaves the partial tree reported rather than presented as a completed delete.

## backup.full-export-import

**Area:** Sessions/configuration · **Status:** partial

Full application backup as a distribution-compatible JSON bundle (version 1, LF UTF-8, CRLF-tolerant, no absolute config_dir, unwrapped base64 sessions.key via SecretVault for cross-platform portability, LF-normalized INI/JSON/text). Covers sessions.ini + sessions.key, workspaces.json, bookmarks.json, preferences.json, accounts.ini, sshhostkeys, and explorer-commands.json. Exported on Debian (LF) restores identically on Fedora, Arch, Windows (CRLF) and Android and vice versa; backup_is_distribution_compatible_between_linux_windows_and_android proves Debian→Windows→Android round-trip, raw base64 key, LF-only decryptable INI and JSON stores, plus fail-closed without key and CRLF file tolerance. Implemented via crates/linscp-engine/src/backup.rs and `backup export|import <file>` in script.rs.

**Next:** No runnable suite evidences this on Android: script needs a `linscp` binary this repo does not build. Runnable residue: backup on Linux and Windows.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Extend the runnable residue (backup) to Android, or cite additional runnable suites there.

## desktop.remote

**Area:** Desktop integration · **Status:** partial

RDP/VNC/SPICE are direct-TCP (3389/5900) with optional SSH jump SOCKS5h relay; X2Go/X11 are SSH-transported via direct-tcpip. Native viewers are resolved via PATH (xfreerdp3→xfreerdp→wlfreerdp/sdl-freerdp, mstsc, open, vncviewer, remote-viewer/spicy, x2goclient/pyhoca-cli, waypipe/ssh -X) with Windows/macOS/Android specifics, and dial the same proxy/tunnel/TLS/SPKI stack as file protocols. A ticket carries the viewer plan of the build it was made on (mstsc + .rdp body on Windows, `open rdp://` on macOS, FreeRDP argv on Linux), and only the ticket that matches the launcher is ever spawned; a host that cannot show a window is handed the .rdp/.vv body or a BrowserGateway hint instead of a spawn, never a spawn it cannot display; XDMCP (UDP 177, unencrypted) is explicitly refused/recommended against. Wayland vs X11 detection drives waypipe vs ssh -X. Verified by unit ticket/argv tests; live viewer integration and ironrdp gateway tests are outstanding.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] Live RDP launch with xfreerdp/mstsc against a throwaway RDP stub verifies argv, port 3389, TLS/NLA option, and jump-host SOCKS5h relay without exposing credentials (live-desktop).
- [ ] Live VNC (5900) and SPICE (5900/.vv) launches verify viewer resolution (tigervnc/remote-viewer), TLS port, and headless .vv/.rdp ticket generation (live-desktop).
- [ ] Live X2Go/NX and X11/Waypipe launches verify SSH-transported NX compression over direct-tcpip, WAYLAND_DISPLAY detection, and that jump-host proxy/TLS/SPKI settings are inherited without fallback (live-desktop).
- [ ] Obtain independent review that ironrdp WASM / Guacamole gateway fallback correctly isolates credentials and that XDMCP (UDP 177) remains refusing/not recommended.

## platform.android-saf-synchronization

**Area:** Packaging/platforms · **Status:** partial

Synchronization with a granted local side plans and applies through LocalFs: the planner walks the tree through the bridge, checksum criteria stat each document fresh and refuse an over-cap file naming it before its bytes are read, downloads land in a private stage and publish across the bridge replacing like the plain path, and uploads stage the granted source and run the guarded upload unchanged from the stage. Granted-side deletions stay lenient; keep-up-to-date cannot watch a content:// tree, so it polls it on the interval instead. The page offers both dialogues for granted folders.

**Next:** The bridge and both remotes are in-memory mocks: no suite has planned against or published into a real DocumentsProvider, so provider behaviour (mtime fidelity after a publish, nested document URIs, large-tree walk time, polling cadence with no watcher) is unproven on a device.

**Acceptance criteria:**

- [ ] Synchronize both directions with delete against a granted folder on an Android device or emulator, covering a checksum comparison, the over-cap refusal and one keep-up-to-date pass.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
