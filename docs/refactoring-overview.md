# Service and frontend refactoring boundaries

The service dispatch table remains in `crates/linscp-service/src/lib.rs`.
Vault lifecycle and SSH-key management endpoints live in `vault.rs`, and
full-backup and key/session interchange endpoints live in `backup.rs`. They
are separate implementations on the same `CommanderService`; routing,
locking, backup formats and error handling remain part of the service contract.
Some key/interchange helpers are still in `lib.rs` because they are shared with
session saving, connection setup and the backup handlers.

`crates/linscp-engine/src/vault_keys.rs` supplies shared vault-file identifier
validation, bounded discovery and no-follow leaf-file reads. Full-backup and
key/session export retain their separate payload formats, limits, selection
and restore policies; these primitives are not a directory snapshot and do not
make concurrent filesystem changes atomic.

The key/session dialog controller is in `source/gui/web/key-session.js`. The
page provides its dependencies and keeps full-backup behavior separately. The
shared frontend build inlines this controller into `ui/dist/index.html` for
both desktop and Android. Translation coverage and literal endpoint checks
inspect the extracted source as well as the page.

After editing localization catalogs, run `python3 tools/update_translations.py`;
use `--check` for a read-only freshness check. See `docs/localization.md`.
For the frontend run `npm ci --prefix ui && npm test --prefix ui`; for repository
checks run `python3 -m unittest discover -s tools/tests` and
`python3 tools/check_upstream_parity.py`. The relevant Rust tests are
`cargo test -p linscp-engine -p linscp-service -- --test-threads=1 --skip live_`.
Live protocol tests and packaged Android/Windows runs require their own
fixtures and environments and are not implied by these checks.
