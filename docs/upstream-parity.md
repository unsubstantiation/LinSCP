# Upstream parity inventory guide

**Full feature parity is not achieved.** LinSCP is an independent, experimental
native GUI application for Linux, Windows and Android, not a build of the upstream application.
Similar interfaces or passing tests do not establish behavioral equivalence.

## Baseline and scope

The inventory is pinned to the upstream development snapshot
[`246bbd42342c4443bd9ff806e91dc0bca9f83869`](https://github.com/winscp/winscp/tree/246bbd42342c4443bd9ff806e91dc0bca9f83869),
not necessarily the latest release. The 2026-10-26 reconciliation reviewed
changes since the previous pin; the weekly upstream workflow checks command
registrations and warns when the baseline needs review.

## Current status

[upstream-parity.json](upstream-parity.json) is the source of truth. The
generated [ledger view](linux-feature-inventory.md) contains scoped status,
evidence and limitations, including historical script registrations and Linux
extensions. These inventory entries do not mean that a standalone CLI is shipped.
The generated [remaining plan](remaining-parity-plan.md) records acceptance
criteria for partial or missing capabilities. The
[final parity review](final-parity-review.md) summarizes recent cross-platform
evidence and unresolved risks.

Run `python3 tools/check_upstream_parity.py` to check inventory consistency and
`python3 tools/check_upstream_parity.py --write-report` to regenerate the views.
`--require-full` fails while tracked gaps remain. The checker is not a test of
behavioral parity or security.
