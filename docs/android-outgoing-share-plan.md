# Android outgoing sharing: implementation and remaining verification

Android's **Files → Share files…** action stages up to 32 selected regular
files (512 MiB total) from app storage, a granted SAF directory, or the selected
remote session. It opens the Android chooser only after all files have been
staged, and does not delete or modify the originals. The app displays the
retention and recipient-copy warning before staging.

Copies live in per-request private cache directories. A non-exported dedicated
FileProvider exposes only that cache subtree through temporary read-only URI
grants, including `ClipData` for multiple files. Old inactive batches are
removed best-effort at a later app launch or share after 24 hours; the OS may
evict cache earlier, cleanup may fail, and a receiving app can keep a copy.
Failed or cancelled preparations are discarded best-effort. Remote staging
reports live file and byte progress through `/api/android/share/status` and
honors cooperative cancellation through `/api/android/share/cancel` (wired to
`LimitedWriter::with_tracking` and the Android share progress modal), while
staying separate from the persistent transfer queue. The size check for remote
files is not a snapshot guarantee.

## Verification still required

The Python tests exercise provider configuration and preparation-script
idempotence; frontend tests exercise selection, consent, live progress polling,
cancellation, and host invocation. Rust tests exercise the bounded writer and
the remote staging path. Those tests are not a substitute for Android build and
device behavior. Before considering this feature verified:

- Build debug and signed release APKs, then use an emulator or device and a
  separate receiver to check exact bytes, names, MIME types, multi-file grants,
  read-only access and absence of access to other app files.
- Exercise both an ordinary shared-storage provider and an opaque-ID SAF
  provider, including provider failures and non-ASCII names.
- Exercise a remote download with server errors, mid-download cancellation,
  source changes and a full device; verify no chooser is shown for incomplete
  or cancelled preparations and originals are unchanged. Test app/activity
  recreation and expiry/cleanup behavior.
