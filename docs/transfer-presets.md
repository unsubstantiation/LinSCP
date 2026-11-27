# Transfer presets and precedence

For each selected top-level item, the queue chooses one preset in this order:

1. An explicit request for `off` or `none` disables presets; an explicit name selects that preset.
2. Otherwise, a site's named preset applies, or the site's `off`/`none` disables matching.
3. Otherwise, filename-mask rules are considered in store order, followed by session-only rules in store order. A filename rule with host, user, or directory conditions must satisfy those conditions as well as the filename mask. Different selected items can match different presets. Directory children use the preset chosen for the top-level directory; rules are not re-selected for each descendant.

A selected preset's mask also filters what is transferred. Explicit per-transfer options take precedence over that preset, then built-in defaults fill in the rest. Transfers are checked before jobs are queued, so an invalid option or missing preset refuses the request rather than queueing only some items. A corrupt preset store is refused unless presets are explicitly disabled. Preset names `auto`, `off`, and `none` are reserved.

In the GUI, untouched default controls inherit the selected or automatically matched preset rather than overriding it. Editing a control records an explicit override, including default-valued choices such as unlimited speed or binary mode. The default transfer-mode choice clears its explicit mode override. For preferences written before override tracking existed, non-default values are retained as overrides; it is impossible to distinguish a deliberately selected default from an untouched default in the old format. Existing users who deliberately chose a default value should select it again to make it explicit. Resetting transfer settings removes the tracked overrides.

Automatic mode by mask decides text conversion for each file; ASCII converts line endings, while binary keeps bytes unchanged. Resume remains subject to [transfer resume safety](transfer-resume-safety.md), including the default refusal of FTP/SFTP resume without explicit best-effort approval. Presets do not bypass guarded-upload, no-overwrite, or Android granted-folder restrictions.

Linux and Windows host tests cover rule conjunction, mixed-file selection, explicit/site precedence, and persisted overrides. The Android emulator smoke includes mixed automatic matching, but that new case and physical Android/third-party server behavior still require an actual run on those platforms.
