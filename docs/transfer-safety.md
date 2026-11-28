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

## Uploads and overwrite

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
