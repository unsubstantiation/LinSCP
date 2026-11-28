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

## Runtime and third-party components

The Rust workspace uses `russh` and `russh-sftp` for SSH transport, Rust
cryptography and TLS crates, and Tauri for the native shell. The embedded
terminal uses `alacritty_terminal` 0.26 (Apache-2.0). Platform runtimes and
system libraries may also be needed. See `NOTICE`, `debian/copyright`, the
workspace manifests and `Cargo.lock` for component information; review the
actual dependency and license set for each distribution target. A lockfile
records versions, not a complete license inventory.

## Repository history

Earlier commits and historical release notes may describe components that
were present at the time. They are not part of the current source tree or
current binary. The current license and component inventory is defined by the
tracked files and notices listed above; do not treat historical implementation
notes as a description of current dependencies.
