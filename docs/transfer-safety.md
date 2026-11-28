# Transfer safety and protocol boundaries

**LinSCP is experimental and not ready for production transfers.** The
protocol/server combinations below have implementation and fixture coverage,
not universal interoperability guarantees. Operations can fail after remote
state changes; inspect both sides before retrying.

## Resume, staging and cancellation

See [resume safety](transfer-resume-safety.md) for the exact opt-in and trust
requirements. WebDAV/S3 verified downloads retransmit and compare the saved
prefix under a strong ETag; this relies on server enforcement and an unchanged
ETag need not identify a unique version. FTP/SFTP cannot pin a source snapshot:
resume requires explicit best-effort approval. GUI upload resume, ASCII resume,
and verified resume to Android granted folders are refused. Existing
checkpoints are not modified or deleted; a network failure may save a new one.

Queued transfers support cooperative cancellation. Interrupted FTP/FTPS
transfers invalidate their control connection and require reconnecting. Fresh
downloads use temporary staging with best-effort cleanup; cleanup can fail.
Staging and publication require a trusted destination directory and ancestors;
pathname races and same-account access remain possible.

## Directories and moves

SFTP and WebDAV directory downloads can stage a new tree before publication;
explicitly approved merges do not replace conflicting files, but publication is
not transactional and interruption may leave files behind. WebDAV directory
copies require acknowledgement that trees are not snapshots and path changes
can redirect writes. Other directory merges are unsupported. SFTP and WebDAV
remote-to-remote directory copies use local staging and risk confirmation; they
do not merge and can leave partial trees. SFTP cannot pin source versions;
WebDAV pins individual files but a collection ETag may not cover descendants.

WebDAV file moves to a new local destination use conditional GET and DELETE;
a failed or ambiguous delete may leave a duplicate. WebDAV same-session moves
use a strong ETag and no-replace MOVE; directory ETags need not cover every
child, and a lost response may mean the move happened. Cross-server WebDAV file
moves require confirmation, use an ETag-pinned download and exclusive upload,
and are not transactional. Cross-server directory moves and S3-source moves
are unsupported. Local moves require a new destination on the same filesystem.

## Android granted-folder publication

The provider bridge checks for an existing destination before writing, but the
check and write are **not atomic**. A document created or replaced concurrently
can be overwritten even when a no-overwrite operation was requested. Provider
writes can also leave partial documents on interruption. Avoid concurrent
writers and do not rely on no-clobber guarantees in granted folders. Remote
session downloads and moves into a granted folder, including S3 version
downloads, require explicit per-request acknowledgement of this risk. This
confirmation does not cover every other provider operation, such as local-pane
copies or synchronization. Verified resume remains refused until checkpointing and publication have an adequate
provider-specific safety contract.

## Uploads and overwrite

A local-to-remote file move uploads first, then checks the local source's
metadata before deleting it. A detected change or replacement leaves the source
in place and reports an incomplete move. This is best effort, not atomic:
metadata can miss changes, and the pathname can change between the check and
deletion. Use trusted directories and avoid concurrent local writers. Moves
from Android granted folders to remote sessions are refused because the provider
bridge does not offer conditional deletion; copy and verify before manually
deleting the source. A remote-to-local move checks cancellation before attempting
source deletion, but cancellation during an already-started delete cannot
reverse it.

- No-overwrite SFTP, WebDAV and S3 uploads use exclusive creation. S3 uploads
  using conditional publication are limited to 1 GiB. Queued WebDAV/S3
  overwrites require a strong ETag and server-enforced conditions; unsupported
  overwrites are refused.
- FTP/FTPS uploads require explicit acceptance of a destination rename race and
  a server supporting STOU with an RFC 1123 FILE response. A competing target
  can be overwritten after the check; a failure can leave a temporary file.
  Existing destinations need separate overwrite approval. Do not use this mode
  where no-clobber guarantees are required.
- FTP/SFTP cannot safely identify an interrupted upload for deletion by
  pathname, so LinSCP leaves it for inspection rather than deleting a file a
  different client may have replaced. The internal script engine has a
  separately acknowledged, racy SFTP staged-overwrite mode; the GUI queue does
  not offer it. No standalone CLI is shipped.
- On WebDAV servers supporting conditional lock-null resources, new uploads can
  stage under a random locked name and attempt lock-conditional cleanup. Failed
  cleanup is retried in memory, not durably; locks can expire. Servers without
  this support fall back to direct exclusive or conditional PUT. Approved
  lock-capable overwrites depend on source-lock and destination-ETag conditions
  being enforced by the server.
- S3 uploads over 16 MiB use multipart upload IDs. Abort or initiation can be
  unconfirmed, in-flight parts can survive an abort, and a lost completion reply
  can mean the object exists. Known IDs are journaled for later retries using
  file locks; recovery assumes trusted configuration storage, working OS locks
  and provider upload-ID uniqueness. A crash before recording the ID cannot be
  recovered this way. Configure a lifecycle rule for abandoned multipart uploads.

Loopback fixture tests cover selected SFTP, WebDAV, FTP/FTPS and S3 operations;
they do not certify all third-party servers. See the
[final parity review](final-parity-review.md) for evidence and remaining gaps.

Linux and Windows host regressions for changed-source detection, a stable move,
and granted-folder move refusal passed in [CI run 46131197417](https://github.com/unsubstantiation/LinSCP/actions/runs/46131197417). They use a mock remote session and provider; they do not establish real-server or Android-device behavior.
