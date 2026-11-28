# Native and Android integration boundaries

## Desktop drops and URI activation

Tauri's event listener uses a numeric callback registered with
`transformCallback`. The host includes the drop's physical position; the page
converts it to CSS pixels for pane hit-testing, with the focused pane as a
fallback. The path list is authoritative when supplied, so its first path is
not added again from the legacy `source_path` field. Top-level dropped names
with leading or trailing whitespace are refused rather than silently renamed by
transfer name normalization. Other unsupported paths and symbolic links are
also refused. A failed multi-item upload staging attempt removes its whole
private batch, including a partially written current file. Native filesystem
sources for remote drops stream in 64 KiB chunks under the configured bounds.
Local-pane file copies and SAF URI drop sources can still read a whole file into
memory; the streaming statement does not apply to those paths.

The jsdom test models Tauri's callback-ID contract and pane coordinates; the
Rust service tests exercise path drops and conflicts. Neither proves a real
operating-system drag into WebKit/GTK or WebView2. Existing GIO tests select an
isolated XDG default and launch a custom-prefix desktop entry, and existing
Linux/Windows launcher tests cover URL delivery and review, but these do not
establish real user desktop defaults or hostile URL handling on all platforms.

## Android shares

Incoming content URIs are staged in app-private cache, with a 100-item and a
512 MiB batch limit. Failure anywhere in staging removes batches already
created in that attempt; unsupported URI schemes fail rather than being
silently skipped. A successfully staged SEND intent records pending paths in
app-private preferences. The Rust bridge peeks and publishes one deterministic
manifest per file before acknowledging it, retries failures and reports them to
the page, and serializes concurrent polls. Pending batches are excluded from
age-based cleanup. Manifest claims use a same-directory rename so concurrent
consumers cannot both claim the same manifest on Windows or Linux.

This is not a transactional or exactly-once delivery guarantee: a process death
between staging bytes and saving the preference can orphan a cache batch; a
crash during manifest claim/queueing can leave a claim or lose an unqueued
item. An acknowledgement failure combined with another consumer removing the
manifest can permit a duplicate on retry. Cache eviction, clearing app data,
provider revocation and device storage failures remain external limitations.
The explicit `linscp_handle_share_intent` command reports manifest failure but
may leave its staged cache files for age-based cleanup; its caller must retry
with the source URIs. Automatic share uploads use `/api/shell/consume`, not the
native-drop conflict dialog: per-item queue refusals are reported, and a
consumed refusal is not automatically retried.

The Android emulator suite uses the external-storage DocumentsProvider and a
DocumentsUI grant. Other providers, two independently granted trees, real share
sheet senders and physical devices remain unverified. In particular the test's
explicit SEND intent does not prove Android's share-sheet resolver selected the
app, nor does it exercise SEND_MULTIPLE or an upload conflict.

## Evidence

- [Android and desktop integration run](https://github.com/unsubstantiation/LinSCP/actions/runs/46112542095): unsigned APK build, external-storage provider and explicit SEND emulator scenarios; Linux and Windows native-shell builds and targeted claim/drop tests. The SEND is explicitly addressed to the app, not selected by the Android share sheet.
- The local UI suite exercises the callback-ID and scaled hit-test stubs. Local GIO tests launch an isolated-default custom-prefix entry into a stub executable. These are not physical desktop drag or default-selection tests.
- [Final desktop drop regression run](https://github.com/unsubstantiation/LinSCP/actions/runs/46113595393): Linux and Windows bounded staging, native path handling and concurrent manifest claim tests, including a single native upload and over-limit refusal.

- [Final Android review](https://github.com/unsubstantiation/LinSCP/actions/runs/46124619130): unsigned debug APKs for both ABIs and the API 35 x86_64 emulator smoke passed on the later code. The scope remains the specific emulator scenarios above, not physical devices, arbitrary providers or share-sheet selection.
