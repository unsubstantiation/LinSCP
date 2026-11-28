# Localization, XML and SCP: product-priority assessment

This is an engineering recommendation for the current GUI-only product, not a
claim of full upstream parity or a commitment to ship every upstream feature.
The retired command-line executable, .NET assembly and PowerShell interfaces
are not shipped. See [the ledger](remaining-parity-plan.md) for open criteria.

## Languages

The shipped English, Spanish, German and French catalogs are the current
supported set. Adding another language is worthwhile when there is a target
user community, a maintained terminology/style review and capacity to review
security warnings and future changes. No demand or reviewer evidence in this
repository establishes which language should come next. Do not fill catalogs
with unreviewed machine translations or English placeholders simply to raise a
parity count.

A new locale currently needs both source catalog domains, regeneration,
registration in Rust's explicit `include_str!` list, UI selection tests and
human review. There are 1,772 English GUI keys and 459 legacy/engine CLI keys
at this assessment; these totals change as the product changes. The GUI has a
singular/other interface and Rust has hand-coded singular rules. Languages
requiring additional CLDR plural categories need a plural-model change, not
just another JSON file. Check RTL layout, input methods, font coverage,
confirmation prompts and rendered security messages as applicable. Catalog and
placeholder tests are not evidence of translation quality or complete coverage
of dynamic server/OS errors. Protocol data, filenames and diagnostics must not
be translated blindly.

## XML compatibility

The GUI offers an optional XML action log; this is the supported surface, not a
shipped `-xmllog` command-line interface. A project-authored XSD, based on the
pinned upstream emitter, and sample fixtures check a documented subset. Linux
CI checks generated engine and real loopback WebDAV upload/download output
against that XSD; the GUI service has separate interleaved queue/direct-action
coverage. The Linux and Windows focused tests and Linux schema validation,
including the loopback WebDAV test after this change, passed in [branch run
46123944392](https://github.com/unsubstantiation/LinSCP/actions/runs/46123944392).
This is not independent certification against an upstream schema,
a full upstream consumer or all protocols and operation types. Different
operations and failure cases still need live tests. Logs can include paths and
other sensitive operational data; recognized secret redaction is not a general
secret detector. Enabling explicitly sensitive text logging has different
privacy behavior.

GUI queue and direct action appends use a shared in-process lock per complete
record; a transfer does not hold the lock while awaiting the network. A clear
may be followed by later records from an active task. Logging is best-effort:
errors are not surfaced to the operation's caller. A nonempty file without the
expected closing tag is preserved and later appends are refused, but the tail
check does not validate the whole existing document. A crash or I/O failure can
still leave an incomplete log; external writers, other processes and malicious
path replacement are not synchronized by this lock. The preview returns at
most the last 512 KiB; its tail may not itself be a well-formed XML document.
Do not use the log as a transactional or tamper-proof audit trail.

## Recursive SCP wire format

Single-file SCP uses remote `scp -f`/`scp -t` over SSH. The engine can walk a
tree and transfer files individually; it does not send or consume recursive
`D`/`E` directory streams. This is not equivalent to proving that every GUI
operation permits SCP directory transfers: the GUI enforces additional
no-clobber, move and protocol-specific safety rules. Resumption is unsupported.
Existing tests use a mock SSH/SCP server; the historical CLI-dependent live
suite is not evidence for this GUI-only distribution.

Recommendation: defer recursive wire parity until an interoperability or
performance need is demonstrated. A safe implementation needs an explicit
contract for untrusted server record names and directory nesting, depth and
size limits, symlink behavior, exact-size framing, timestamps, destination
containment and no-overwrite guarantees, cancellation, partial-tree cleanup,
and ambiguous disconnects. Test malicious records and failure at every stage
plus live OpenSSH behavior on supported platforms. The shared tree walker is
not a transactional snapshot, and a recursive SCP stream would not provide one.
Do not loosen existing GUI safety refusals merely to implement `D`/`E` records.
