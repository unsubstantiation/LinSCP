# Localization

## Supported languages and coverage

English (`en`), Spanish (`es`), German (`de`) and French (`fr`) catalogs ship
with the application, including whole help messages and plural variants. They
are embedded at build time; there are no
runtime downloads, gettext dependencies or installed OS locale requirements.
A catalog walker reports many strings still answered in English, but does not
prove translation quality or discover every dynamically produced diagnostic.
The native language selector uses the shipped catalogs.

Translated surfaces:

- Browser menus, toolbars, dialogs, help, ARIA labels, tooltips, placeholders,
  host-key verification, queue states and controls, synchronization summaries
  and reasons, search results, editor states and confirmation/error messages.
- The internal script engine has a separate catalog for help, status and
  prompts. The retired standalone command-line executable is not shipped.
- Browser plural forms and decimal/date presentation. CLI/protocol numbers
  remain locale independent.

**This is not complete upstream language coverage.** Only English, Spanish,
German and French are shipped, while upstream ships catalogs for many more
languages.
The inventory therefore retains `locale.translations` as **partial**: catalog
and source checks do not prove that all runtime messages are translated or that
translations are correct.
Server-provided SSH challenges, protocol data, core/OS diagnostic details,
command-console output and logs are deliberately retained verbatim. A browser
operation failure is written into the Logs panel as a translated explanation
with the diagnostic detail, rather than popped up and lost;
file contents, filenames, session names, paths, host-key fingerprints, command
names and API enum values must never be translated.

## Backend locale selection

The backend checks `LINSCP_LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, then `LANG`.
Supported region variants fall back to their language; unknown locales and
`C`/`POSIX` fall back to English. The internal interpreter accepts each
catalog's confirmation letter and `y`/`Y`; noninteractive destructive actions
still fail closed. These settings do not imply a standalone CLI is shipped.

## Browser selection

Use the **Language** selector on the toolbar to choose a shipped language
(English, Español, Deutsch, Français) or the system default. The preference is saved in browser local
storage. A change reloads only the page: backend sessions and queued transfers
continue. Unsaved editor changes require confirmation before reloading.

Without a saved preference, the served page uses the backend's locale selection
(the backend environment precedence, resolved against the catalogs the
page ships, so `de_DE.UTF-8` selects German). A standalone page without backend
configuration chooses the first supported browser language, then English.
Browser region tags such as `es-MX`, `de-AT` and `fr-CA` are supported. When storage is unavailable,
the default still works; a preference change reports the storage failure rather
than silently losing it.

The native GUI communicates with the in-process service rather than spawning
an external CLI. Locale selection must not alter protocol data, paths or API
enumerations.

## Catalog development

1. Edit `source/linux/locales/*.json` for CLI messages, or
   `source/gui/locales/*.json` for browser messages. Both are UTF-8 JSON
   objects; English is an identity catalog and every language must have the
   same keys.
2. Use named placeholders such as `{path}`. Preserve spelling and occurrence
   counts; translations may reorder them. Runtime values are substituted once
   and cannot become more placeholders or format directives.
3. Use `linscp-i18n` translation helpers for internal engine messages and `t`
   for dynamic GUI messages. Use `tn(one, other, count, values)` for the GUI's
   current singular/other forms. Static page text and relevant attributes are
   translated before startup; runtime file/session data is not translated.
   Command names, protocol values and placeholders must remain literal. The
   catalog tests check known literals and placeholders, but they do not discover
   every possible runtime string or establish translation quality.
4. Run `python3 tools/update_translations.py` from the repository root. This
   validates both source catalog sets and regenerates the inline GUI catalog
   in `source/gui/web/index.html`, the unified `locales/*.json`, and the legacy
   `source/linux/Translations.inc` only when that legacy output exists. Commit
   the changed generated files with the source catalogs; do not edit generated
   files by hand. Unexpected files in `locales/` are reported rather than deleted.
   Validation happens before writes, but an I/O error during writing may still
   leave partial output; fix the error and rerun the command.
5. Run the tests below. CI also checks generated-output drift, untranslated
   static browser text, literal `t`/`tn` keys and literal CLI `Translate` keys.

The compiler rejects duplicate/missing keys and malformed/mismatched
placeholders. Inline JSON escapes HTML-significant characters and Unicode line
separators so catalog text cannot close a script tag. Translated dynamic markup
is escaped separately; ordinary translated text uses text nodes.

Adding a language also requires reviewing plural rules (the browser's `tn`
takes one singular and one plural form) and choosing the confirmation hint
letters. The Rust backend explicitly embeds the supported catalog files in
`crates/linscp-i18n/src/lib.rs`; adding a catalog also requires registering it
there and testing selection. The current plural interface only models singular
and other; languages with more categories need design and implementation work. These Linux catalogs
are independent of upstream's Windows resource catalogs; they do not claim to
reproduce all upstream translations.

## Language conventions

Each catalog follows a few choices, so new messages stay consistent with it:

- **German.**
  - Metavariables are translated and capitalized (`<Datei>`, `DATEI`).
  - A stored site is a "Verbindung" (Site Manager: "Verbindungsverwaltung").
  - Error operations are noun phrases that fit
    `{operation} '{path}' nicht möglich.` and
    `{operation} '{path}' ist lokal fehlgeschlagen.`
  - The `{what}` values carry their article ("Der Befehl").
- **French.**
  - A no-break space (U+00A0) goes before `:`, `;`, `?` and `!` and inside
    « ».
  - Elisions use ’. Quoted literals such as `'-filemask'` and `'{path}'`
    keep straight quotes.
  - Error operations are capitalized noun phrases ("Lecture de", "Calcul de
    la somme de contrôle de") that fit `{operation} '{path}' impossible.`
    and `{operation} '{path}' : échec côté local.`
  - The `{what}` values carry their article ("La commande"), and the message
    that uses them avoids gender agreement.
  - Upload is "envoyer", download is "télécharger", and a stored site stays a
    "site".

## Reproducible checks

```sh
python3 tools/update_translations.py --check   # checks all outputs without writing
python3 tools/tests/test_translations.py
make -C source/linux check
```

Run `npm ci --prefix ui && npm test --prefix ui` to build and test the shared
browser page, including the key/session dialog and localization workflows.
CI runs the read-only drift check and translation tests. The lower-level
`compile_translations.py` and `build_unified_locales.py` commands remain
available, but each updates only part of the generated output.

The Makefile, CMake, relocatable installs and Debian packages all embed the same
translations, so none of them needs catalog files at runtime.

For the scope and prioritization of additional languages, see [remaining parity priorities](remaining-parity-priorities.md).
