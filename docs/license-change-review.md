# Current licensing and third-party component review

This document records the licensing of the current LinSCP source tree. It
supersedes earlier repository reviews that described a bundled SSH engine no
longer present in this tree.

It is an engineering inventory, not legal advice. Consult the full license
texts and obtain legal advice for distribution decisions.

## LinSCP code and artwork

LinSCP's own source code is distributed under the PolyForm Noncommercial
License 1.0.0. It grants noncommercial use only; it is not an open-source
license. The required attribution and complete terms are in `LICENSE` and
`NOTICE`.

The logo, icons and screenshots are original project artwork with separate
redistribution terms, described in `NOTICE` and `debian/copyright`.

## Runtime and vendored components

| Component | Use | License / location |
| --- | --- | --- |
| libssh | SSH transport, authentication, host-key handling, SFTP and SCP channels | LGPL-2.1-or-later; linked dynamically from the system; not vendored |
| OpenSSL libcrypto | Hashing, cryptographic helpers and PPK key conversion | Apache-2.0; linked from the system; not vendored |
| libargon2 | Key derivation for encrypted PPK v3 files | CC0 1.0 or Apache-2.0 at the user's option; linked from the system; not vendored |
| xterm.js and FitAddon | Browser-based embedded terminal | MIT; vendored under `source/gui/web/vendor/`, with the notice in `source/gui/web/vendor/LICENSE-xterm.txt` |

The current tree contains no bundled SSH protocol engine. `NOTICE` and
`debian/copyright` identify the current third-party components and their
licenses. Build/package metadata should continue to preserve the applicable
notices and dynamic-linking model.

## Repository history

Earlier commits and historical release notes may describe components that
were present at the time. They are not part of the current source tree or
current binary. The current license and component inventory is defined by the
tracked files and notices listed above; do not treat historical implementation
notes as a description of current dependencies.
