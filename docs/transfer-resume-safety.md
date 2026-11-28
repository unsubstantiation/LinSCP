# Transfer resume safety

Resume is not a general guarantee that a file is a stable snapshot. Use a trusted local destination directory and avoid modifying the partial, destination, or remote source during a transfer.

- Ordinary and GUI verified download resumes copy an existing checkpoint into an owner-restricted temporary directory, verify the copied prefix, and write the remainder to that isolated stage. They never append to, rename, or delete the original checkpoint. It remains available after success or failure; remove it manually when it is no longer needed. Ordinary resume can replace the destination; GUI verified resume publishes without replacing an existing destination.
- This removes the old ordinary-resume race in which a checkpoint pathname could be substituted after verification and then used for writing or publication. It does not defend against a process with the same account's privileges modifying the private stage, or against a hostile actor able to rename the staging directory or its parent. Publication still uses pathnames, so the destination directory and its ancestors must be trusted. No check can stop a writer with sufficient access from changing the destination after publication.
- WebDAV and S3 require a strong ETag and a server that honors conditional requests; versioned S3 also requires version confirmation. FTP and SFTP cannot pin an atomic source snapshot. Their resume is refused by default and is offered only with explicit per-transfer best-effort approval. Concurrent remote changes can still corrupt the result even when size and modification time match. Start a fresh transfer instead if that risk is unacceptable.
- Guarded FTP and SFTP uploads use fresh stages and refuse resume rather than adopting an untrusted remote partial. The GUI currently refuses upload resume for all protocols. Retry a fresh upload; do not assume a remote partial is safe to reuse. Conditional WebDAV/S3 capabilities do not imply GUI upload-resume support.
- Resume with ASCII conversion is refused: byte offsets in converted text do not reliably correspond to source offsets. Select binary mode or restart without resume. Direct ordinary downloads also refuse existing complete, oversized, or unsafe destination files instead of silently overwriting them.
- Android Storage Access Framework granted-folder session transfers do not support verified resume. Restart as a fresh transfer; the provider bridge does not supply the required safe partial-file semantics.

Linux and Windows loopback suites cover checkpoint substitution and interrupted recovery. A packaged Android emulator smoke passed verified WebDAV and best-effort SFTP resume, including refusal cases ([run 46045911600](https://github.com/unsubstantiation/LinSCP/actions/runs/46045911600)). Provider behavior, third-party server interoperability, and physical Android devices remain open validation work. These limitations are not evidence of atomic snapshot support.

The internal non-GUI S3 multipart path now stores a SHA-256 digest with each
confirmed part and only reuses it when the retry supplies matching bytes. It
scopes new checkpoints by endpoint/account and serializes attempts sharing one
store. It rejects source length changes before completion. This is not GUI
upload resume: GUI conditional uploads still start fresh and retain their
existing no-overwrite preconditions. The old bucket/key-only checkpoint records
are not adopted; their unfinished uploads may remain, so an S3 lifecycle rule
is still needed. The store lock is process-local and does not coordinate
separately constructed stores or processes. Source changes during a single
attempt and server behavior remain limitations.

The multipart checkpoint regressions passed against a local HTTPS S3 fixture on
Linux and Windows in [CI run 46131724564](https://github.com/unsubstantiation/LinSCP/actions/runs/46131724564). They cover changed and hashless parts, endpoint separation, and short/long sources; they are not production S3 provider or multi-process validation.
