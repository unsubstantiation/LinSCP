# Linux localization

## Supported languages and coverage

English (`en`), Spanish (`es`), German (`de`) and French (`fr`) catalogs ship
with the application. There are 456 CLI catalog entries and 656 browser entries,
including whole help messages and plural variants. They are embedded at build time; there are no
runtime downloads, gettext dependencies or installed OS locale requirements.
A catalog walker reports interface strings still answered in English so a new
message cannot slip through untranslated. The language selector is filled from
the shipped catalogs.

Translated surfaces:

- Browser menus, toolbars, dialogs, help, ARIA labels, tooltips, placeholders,
  host-key verification, queue states and controls, synchronization summaries
  and reasons, search results, editor states and confirmation/error messages.
- The whole command-line client: the per-command help texts, the status,
  argument, switch and engine messages of the script engine, the operations
  the error helpers name, the option listing, `-help` and option errors,
  connection status, host-key warnings, client-side key passphrase prompts,
  overwrite/delete confirmations and confirmation-answer hints.
- Browser plural forms and decimal/date presentation. CLI/protocol numbers
  remain locale independent.

**This is not complete upstream language coverage.** Only English, Spanish,
German and French are shipped, while upstream ships catalogs for many more
languages.
The inventory therefore retains `locale.translations` as **partial**, now for
the missing languages alone: every message the client prints in this build
goes through a catalog, and the compiler refuses a new one that does not.
Server-provided SSH challenges, protocol data, core/OS diagnostic details,
command-console output and logs are deliberately retained verbatim. A browser
operation failure shows a translated explanation with the diagnostic detail;
file contents, filenames, session names, paths, host-key fingerprints, command
names and API enum values must never be translated.

## CLI selection

```sh
LINSCP_LANGUAGE=es linscp -help
LANG=de_DE.UTF-8 linscp -batch -command='nosuchcommand'
```

The first nonempty variable wins: `LINSCP_LANGUAGE`, `LC_ALL`, `LC_MESSAGES`,
then `LANG`. An exact catalog is preferred; `es_MX.UTF-8` and `es_ES@formal`
fall back to `es`, `de_AT.UTF-8` to `de` and `fr_CA.UTF-8` to `fr`. Unknown
locales and `C`/`POSIX` use English. Selection changes
messages only, not the process's numeric locale or protocol serialization.

Confirmation hints are translated: `[S/n]`/`[s/N]` in Spanish, `[J/n]`/`[j/N]`
in German and `[O/n]`/`[o/N]` in French. The client accepts the letter a hint shows for yes, in either case,
and always `y`/`Y` for compatibility; any other answer is no. Noninteractive
destructive actions still fail closed; translating a prompt does not authorize
an action.

## Browser selection

Use the **Language** selector on the toolbar to choose a shipped language
(English, Español, Deutsch, Français) or the system default. The preference is saved in browser local
storage. A change reloads only the page: backend sessions and queued transfers
continue. Unsaved editor changes require confirmation before reloading.

Without a saved preference, the served page uses the backend's locale selection
(the same environment precedence as the CLI, resolved against the catalogs the
page ships, so `de_DE.UTF-8` selects German). A standalone page without backend
configuration chooses the first supported browser language, then English.
Browser region tags such as `es-MX`, `de-AT` and `fr-CA` are supported. When storage is unavailable,
the default still works; a preference change reports the storage failure rather
than silently losing it.

The GUI always runs its internal CLI subprocesses with
`LINSCP_LANGUAGE=en`. The browser localizes their structured presentation
separately. This is essential: language-dependent messages must not change the
machine protocol, parsed sync plans, progress reports or error handling.

## Catalog development

1. Edit `source/linux/locales/*.json` for CLI messages, or
   `source/gui/locales/*.json` for browser messages. Both are UTF-8 JSON
   objects; English is an identity catalog and every language must have the
   same keys.
2. Use named placeholders such as `{path}`. Preserve spelling and occurrence
   counts; translations may reorder them. Runtime values are substituted once
   and cannot become more placeholders or format directives.
3. Use `Texts::Translate` for identified CLI messages; use `t` for dynamic
   browser messages. Use `tn(one, other, count, values)` for singular/plural
   forms; the page language's CLDR plural rule picks the form, so French
   treats 0 as singular. Static page text and `title`, `aria-label` and
   `placeholder` attributes are translated before startup. `code` and `kbd`
   text and input values are not rewritten. Dynamic file/session data is
   never walked or translated.
   A message that the command-line client prints has to go through
   `Texts::Translate`: the compiler rejects a `Console` call that prints a
   plain literal (including `Confirm` and `ReadPassword` prompts and the
   editor's `mConsole` calls), a command help text that nobody translated
   and an error operation that is not in the catalog.
   Switch names, enumerated values (`on|off`, `binary|ascii|automatic`),
   command and option names, quoted commands such as `'option preset off'`
   and protocol words (`LSCP-RESULT`, `SizeBytes`, `ModifiedEpoch`) stay
   verbatim, because users type them and programs read them. Metavariables
   such as `<file>` or `FILE` may be translated. The translation tests
   enforce this, check that each catalog's `-help` lists every option and
   command in the English order, and check that both confirmation hints
   offer one consistent yes letter.
4. Run `python3 tools/compile_translations.py`. Commit the catalogs together
   with `source/linux/Translations.inc` and the generated inline catalog block
   in `source/gui/web/index.html`. Do not hand-edit generated blocks.
5. Run the tests below. CI also checks generated-output drift, untranslated
   static browser text, literal `t`/`tn` keys and literal CLI `Translate` keys.

The compiler rejects duplicate/missing keys and malformed/mismatched
placeholders. Inline JSON escapes HTML-significant characters and Unicode line
separators so catalog text cannot close a script tag. Translated dynamic markup
is escaped separately; ordinary translated text uses text nodes.

Adding a language also requires reviewing plural rules (the browser's `tn`
takes one singular and one plural form) and choosing the confirmation hint
letters. The selector and the backend's locale selection are filled from the
shipped catalogs, so a new catalog needs no code change. These Linux catalogs
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
python3 tools/compile_translations.py --check   # fails if generated output is stale
python3 tools/tests/test_translations.py
make -C source/linux check
```

The browser tests in `source/gui/tests/` (`ClientTest.js`,
`LocalizationTest.js`) need Node and `jsdom`, which is an optional test
dependency. CMake registers them with CTest only when both are installed. The
live SFTP suite needs `paramiko`. CI runs the drift check and the translation
tests.

The Makefile, CMake, relocatable installs and Debian packages all embed the same
translations, so none of them needs catalog files at runtime.
